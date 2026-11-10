"""The one error boundary: under UNIFI_REDACT_SECRETS no credential value reaches the client.

``SecretScrubMiddleware`` passes the final text of every tool error through
``redaction.mask_error_text``. These tests raise errors from deliberately UNMASKED
builders and from the real resolution builders (the resolution probes), through a real
MCP client session, and assert the credential marker never arrives.
"""

from __future__ import annotations

import json
from collections.abc import Awaitable, Callable
from typing import Any
from unittest.mock import AsyncMock

import pytest
from fastmcp import Client
from fastmcp.exceptions import ToolError

from tests import upstream_harness as uh
from unifi_fabric import server
from unifi_fabric.client import upstream_error_text
from unifi_fabric.families.site_manager import site_manager
from unifi_fabric.redaction import REDACTION_MASK, mask_error_text, redact_credentials
from unifi_fabric.registry import FetchedRecords, match_ea_site, match_host

MARKER = "synthetic-boundary-MARKER"
SITE_UUID = "00000000-0000-4000-8000-000000000001"

#: A credential pair in each quoting a message builder can meet.
CREDENTIAL_FORMS = {
    "plain": json.dumps({"password": MARKER, "reason": "synthetic"}),
    "apostrophe": json.dumps({"password": "it's " + MARKER}),
    "escaped-quote": json.dumps({"password": 'a"b ' + MARKER}),
}


def unmasked_message() -> str:
    """Every form a credential takes once formatted, with no masking at all."""
    plain = CREDENTIAL_FORMS["plain"]
    apostrophe = CREDENTIAL_FORMS["apostrophe"]
    escaped = CREDENTIAL_FORMS["escaped-quote"]
    nested = json.dumps({"outer": {"rows": [{"x_passphrase": MARKER}]}})
    record = {"id": "site-1", "api_key": MARKER, "token": "it's " + MARKER}
    return (
        f"plain {plain}; apostrophe {apostrophe!r}; escaped {escaped!r}; "
        f"nested {nested!r}; repr of a dict {record!r}; "
        f"json-encoded json {json.dumps({'body': escaped})}; "
        f"repr of json-encoded json {json.dumps({'body': apostrophe})!r}; "
        f"call(password={MARKER!r}) secret={MARKER}"
    )


def _install(monkeypatch: pytest.MonkeyPatch, *, redact: bool = True) -> Any:
    if redact:
        monkeypatch.setenv("UNIFI_REDACT_SECRETS", "1")
    else:
        monkeypatch.delenv("UNIFI_REDACT_SECRETS", raising=False)
    return uh.install(monkeypatch, uh.FakeUpstream(), tool_mode="full", redact_secrets=redact)


async def _client_error(
    monkeypatch: pytest.MonkeyPatch, failing: Callable[[], Awaitable[Any]]
) -> str:
    """The error text an MCP client receives when ``list_hosts`` runs ``failing``."""

    async def tool_body(*_args: Any, **_kwargs: Any) -> Any:
        return await failing()

    monkeypatch.setattr(site_manager, "list_hosts", tool_body)
    async with Client(server.mcp) as mcp_client:
        with pytest.raises(ToolError) as caught:
            await mcp_client.call_tool("list_hosts", {})
    return str(caught.value)


@pytest.mark.parametrize("error", [ToolError, ValueError, RuntimeError])
async def test_boundary_masks_an_unmasked_builder(monkeypatch, error):
    _install(monkeypatch)

    async def failing() -> None:
        raise error(unmasked_message())

    text = await _client_error(monkeypatch, failing)
    assert MARKER not in text
    assert REDACTION_MASK in text
    assert "repr of a dict" in text and "'id': 'site-1'" in text  # The evidence stays.


async def test_boundary_negative_control(monkeypatch):
    """Without the boundary call the same message reaches the client unmasked."""
    _install(monkeypatch)
    monkeypatch.setattr(server, "mask_error_text", lambda text: text)

    async def failing() -> None:
        raise ToolError(unmasked_message())

    assert MARKER in await _client_error(monkeypatch, failing)


async def test_boundary_is_opt_in(monkeypatch):
    """With UNIFI_REDACT_SECRETS off the error is the builder's text, byte for byte."""
    _install(monkeypatch, redact=False)

    async def failing() -> None:
        raise ToolError(unmasked_message())

    assert await _client_error(monkeypatch, failing) == unmasked_message()


@pytest.mark.parametrize(
    "text",
    [
        "plain text, status=500 id=abc count=3",
        json.dumps({"name": "a", "rows": [1, 2], "nextToken": "cursor-1"}),
        "{'id': 'x', 'token_count': 5, 'profileToken': 'p1'}",
        "ambiguous site 'Office': 2 sites share that name (Office (a); Office (b))",
    ],
)
def test_mask_error_text_leaves_other_text_unchanged(text):
    assert mask_error_text(text) == text


def test_mask_error_text_masks_every_form_and_is_idempotent():
    once = mask_error_text(unmasked_message())
    assert MARKER not in once
    assert mask_error_text(once) == once
    for form in CREDENTIAL_FORMS.values():
        for rendered in (form, repr(form), json.dumps({"d": form}), repr(json.dumps({"d": form}))):
            assert MARKER not in mask_error_text(rendered), rendered


# Quote boundaries must survive every enclosing JSON/Python representation.
BOUNDARY_ENCODERS = {
    "repr-dict": repr,
    "repr-json": lambda row: repr(json.dumps(row)),
    "json-encoded-json": lambda row: json.dumps({"body": json.dumps(row)}),
    "repr-json-encoded-json": lambda row: repr(json.dumps({"body": json.dumps(row)})),
}


@pytest.mark.parametrize("form", BOUNDARY_ENCODERS)
@pytest.mark.parametrize("enabled", [False, True])
@pytest.mark.parametrize(
    "value",
    [
        ['quoted " ] } first', MARKER],
        ["apostrophe ' [ { first", MARKER],
        ["escaped " + chr(92) + '" ] first', MARKER],
        "it's " + MARKER + chr(92),
        "it's " + MARKER + chr(92) * 2,
    ],
    ids=[
        "quote-brackets",
        "apostrophe-brackets",
        "slash-quote-bracket",
        "trailing-slash",
        "two-trailing-slashes",
    ],
)
async def test_boundary_preserves_evidence_after_escaped_credentials(
    monkeypatch, form, enabled, value
):
    _install(monkeypatch, redact=enabled)
    record = {"password": value, "id": "site-1", "reason": "synthetic-rejected"}
    message = BOUNDARY_ENCODERS[form](record)

    async def failing() -> None:
        raise ToolError(message)

    text = await _client_error(monkeypatch, failing)
    if not enabled:
        assert text == message
        return
    assert MARKER not in text
    assert REDACTION_MASK in text
    assert "site-1" in text
    assert "synthetic-rejected" in text
    assert text[text.index("id") :] == message[message.index("id") :]
    assert mask_error_text(text) == text


# Whole keys: a key is read whole and decoded before the credential rules apply, so every
# key redact_credentials masks in a response is masked in error text too.

BACKSLASH = chr(92)
#: ``password`` with its ``w`` written as a literal JSON escape (backslash, u0077).
ESCAPED_PASSWORD = "pass" + BACKSLASH + "u0077ord"
#: Keys outside the old ``[A-Za-z_][\w-]*`` key pattern that redact_credentials masks.
WIDE_KEYS = ("1_password", "service.auth_password", "é_password")
#: Look-alikes no credential rule matches: they must reach the client unchanged.
LOOKALIKE_KEYS = (
    "1_password_hint",
    "service.auth_password_policy",
    "é_passwordless",
    ESCAPED_PASSWORD + "_policy",
)


def _key_forms(key: str) -> dict[str, str]:
    """``key: MARKER`` in each form an error message carries a record in."""
    record = {key: MARKER, "id": "site-1"}
    return {
        "repr-dict": repr(record),
        "repr-json": repr(json.dumps(record)),
        "repr-json-unicode": repr(json.dumps(record, ensure_ascii=False)),
        "json-encoded-json": json.dumps({"body": json.dumps(record)}),
        "repr-json-encoded-json": repr(json.dumps({"body": json.dumps(record)})),
        "kv": f"{key}={MARKER} id=site-1",
        "kv-quoted": f"call({key}={MARKER!r}, id='site-1')",
    }


def _escaped_key_json() -> str:
    """JSON text whose credential key is spelled with an escape: ``pass\\u0077ord``."""
    return '{"' + ESCAPED_PASSWORD + '": "' + MARKER + '", "id": "site-1"}'


WIDE_KEY_CASES = {
    f"{key}:{form}": text for key in WIDE_KEYS for form, text in _key_forms(key).items()
}
WIDE_KEY_CASES.update(
    {
        "escaped-password:repr-json": repr(_escaped_key_json()),
        "escaped-password:json": _escaped_key_json(),
        "escaped-password:json-encoded-json": json.dumps({"body": _escaped_key_json()}),
        "escaped-password:repr-json-encoded-json": repr(json.dumps({"body": _escaped_key_json()})),
        "escaped-password:kv": f"{ESCAPED_PASSWORD}={MARKER}&id=site-1",
    }
)


def test_wide_keys_are_credentials_for_redact_credentials_too():
    """The error scan applies the response rules: each case is masked in a response."""
    for key in (*WIDE_KEYS, "password"):
        assert redact_credentials({key: MARKER}) == {key: REDACTION_MASK}
    for key in LOOKALIKE_KEYS:
        assert redact_credentials({key: MARKER}) == {key: MARKER}
    assert json.loads(_escaped_key_json()) == {"password": MARKER, "id": "site-1"}


@pytest.mark.parametrize("case", list(WIDE_KEY_CASES))
async def test_boundary_masks_whole_and_escaped_keys(monkeypatch, case):
    """Through a real MCP client: no wide or escaped credential key's value arrives."""
    _install(monkeypatch)
    message = f"upstream rejected the body: {WIDE_KEY_CASES[case]}"

    async def failing() -> None:
        raise ToolError(message)

    text = await _client_error(monkeypatch, failing)
    assert MARKER not in text
    assert REDACTION_MASK in text
    if ":kv" in case:
        assert "site-1" not in text
    else:
        assert "site-1" in text


@pytest.mark.parametrize("case", list(WIDE_KEY_CASES))
async def test_whole_and_escaped_keys_negative_control(monkeypatch, case):
    """Without the boundary call each case reaches the client unmasked."""
    _install(monkeypatch)
    monkeypatch.setattr(server, "mask_error_text", lambda text: text)
    message = f"upstream rejected the body: {WIDE_KEY_CASES[case]}"

    async def failing() -> None:
        raise ToolError(message)

    assert MARKER in await _client_error(monkeypatch, failing)


@pytest.mark.parametrize("key", LOOKALIKE_KEYS)
async def test_lookalike_keys_reach_the_client_unchanged(monkeypatch, key):
    """Negative control on the rules: a look-alike key is not masked, in any form."""
    _install(monkeypatch)
    message = "; ".join(_key_forms(key).values())

    async def failing() -> None:
        raise ToolError(message)

    assert await _client_error(monkeypatch, failing) == message


@pytest.mark.parametrize(
    "text",
    [
        f"service.password={MARKER}",
        f"url /api/v1/password={MARKER}",
        f"line one{BACKSLASH}npassword={MARKER}",
    ],
)
def test_bare_key_segments_still_mask(text):
    """A bare key no rule matches is retried from each later segment, as before."""
    masked = mask_error_text(text)
    assert MARKER not in masked
    assert mask_error_text(masked) == masked


# The resolution probes: the real resolution builders, each failing on an upstream value
# that holds a credential JSON string (plain, apostrophe, escaped quote).


async def _site_not_found(monkeypatch, client, secret):
    """registry._valid_site_choices: a site with a JSON description AND a name."""
    registry = server._registry
    sites = FetchedRecords([{"id": SITE_UUID, "description": secret, "name": "Office"}])
    monkeypatch.setattr(registry, "get_sites", AsyncMock(return_value=sites))
    await registry.resolve_site_id("missing", "host-1")


async def _site_name_not_found(monkeypatch, client, secret):
    """registry._valid_site_choices: a site with a JSON name and a description."""
    registry = server._registry
    sites = FetchedRecords([{"id": SITE_UUID, "description": "Office", "name": secret}])
    monkeypatch.setattr(registry, "get_sites", AsyncMock(return_value=sites))
    await registry.resolve_site_id("missing", "host-1")


async def _proxy_site_ambiguous(monkeypatch, client, secret):
    """registry._match_proxy_site: two sites share a name, one with a JSON id."""
    registry = server._registry
    sites = FetchedRecords([{"id": secret, "name": "same"}, {"id": "other", "name": "same"}])
    monkeypatch.setattr(registry, "get_sites", AsyncMock(return_value=sites))
    await registry.resolve_site_id("same", "host-1")


async def _host_ambiguous(monkeypatch, client, secret):
    """registry._describe_host: two consoles share a hostname, one with JSON fields."""
    match_host(
        [
            {"id": secret, "reportedState": {"hostname": "same", "name": secret}},
            {"id": "other", "reportedState": {"hostname": "same"}},
        ],
        "same",
    )


async def _ea_site_ambiguous(monkeypatch, client, secret):
    """registry.match_ea_site: two Site Manager sites share a name, JSON siteId/hostId."""
    match_ea_site(
        [
            {"siteId": secret, "hostId": secret, "meta": {"name": "same"}},
            {"siteId": "other", "meta": {"name": "same"}},
        ],
        "same",
        partial=[],
        max_pages=None,
    )


async def _ea_site_not_found(monkeypatch, client, secret):
    """registry.match_ea_site: the valid names list holds a JSON meta.name."""
    match_ea_site(
        [{"siteId": "other", "meta": {"name": secret}}], "missing", partial=[], max_pages=None
    )


def _search(partial: bool):
    async def probe(monkeypatch, client, secret):
        """search_across_sites/_proxy_site_for_ea: a JSON siteId the console cannot map."""
        registry = server._registry
        sites = (
            FetchedRecords(
                [{"id": SITE_UUID, "description": "ea"}], incomplete_reason="synthetic partial"
            )
            if partial
            else FetchedRecords([])
        )
        ea_sites = [{"hostId": "valid-host", "siteId": secret, "meta": {"name": "ea"}}]
        monkeypatch.setattr(registry, "get_ea_sites", AsyncMock(return_value=ea_sites))
        monkeypatch.setattr(registry, "resolve_key_for_host", AsyncMock(return_value=None))
        monkeypatch.setattr(registry, "get_sites", AsyncMock(return_value=sites))
        await site_manager.search_across_sites(client, registry, "")

    return probe


PROBES = {
    "site-not-found-description": _site_not_found,
    "site-not-found-name": _site_name_not_found,
    "proxy-site-ambiguous": _proxy_site_ambiguous,
    "host-ambiguous": _host_ambiguous,
    "ea-site-ambiguous": _ea_site_ambiguous,
    "ea-site-not-found": _ea_site_not_found,
    "search-unmapped": _search(partial=False),
    "search-label-on-partial": _search(partial=True),
}


@pytest.mark.parametrize("form", list(CREDENTIAL_FORMS))
@pytest.mark.parametrize("probe", list(PROBES))
async def test_resolution_probes_mask_per_site_and_end_to_end(monkeypatch, probe, form):
    client = _install(monkeypatch)
    secret = CREDENTIAL_FORMS[form]
    # Per site: the builder's own message is already masked, before any boundary.
    with pytest.raises((ValueError, RuntimeError)) as direct:
        await PROBES[probe](monkeypatch, client, secret)
    assert MARKER not in str(direct.value)
    # End to end: the same failure inside a tool call reaches the client masked.
    text = await _client_error(monkeypatch, lambda: PROBES[probe](monkeypatch, client, secret))
    assert MARKER not in text
    assert REDACTION_MASK in text


# Fixed property corpus: 48 combinations plus every earlier round above, each
# exercised both at the final MCP boundary and through the upstream formatter.
PARSER_VALUES = (
    MARKER,
    "it's " + MARKER + chr(92),
    ['quote " ] } first', MARKER],
    ["apostrophe ' [ { first", MARKER],
    [chr(92) + '" ] first', MARKER],
    {"nested": [{"token": MARKER}]},
)
PARSER_ENCODERS = (
    repr,
    json.dumps,
    lambda row: repr(json.dumps(row)),
    lambda row: json.dumps({"body": json.dumps(row)}),
)
PARSER_CORPUS = [
    prefix
    + encode({"password": value, "id": "site-1", "reason": "synthetic-rejected"})
    + "; following-id=console-id; reason=retry-read"
    for prefix in ("upstream: ", "controller couldn't apply: ")
    for encode in PARSER_ENCODERS
    for value in (*PARSER_VALUES, ['a" ] }', MARKER])
]


@pytest.mark.parametrize("message", PARSER_CORPUS)
@pytest.mark.parametrize("upstream", [False, True])
async def test_complete_literal_corpus_real_client(monkeypatch, message, upstream):
    from unifi_fabric.client import upstream_error_text

    client = _install(monkeypatch)

    async def failing() -> None:
        text = upstream_error_text(ValueError(message), client) if upstream else message
        raise ToolError(text)

    text = await _client_error(monkeypatch, failing)
    assert MARKER not in text
    assert REDACTION_MASK in text
    for evidence in ("site-1", "synthetic-rejected", "console-id", "retry-read"):
        assert evidence in text
    assert mask_error_text(text) == text


@pytest.mark.parametrize("message", PARSER_CORPUS)
async def test_complete_literal_corpus_negative_control(monkeypatch, message):
    _install(monkeypatch)
    monkeypatch.setattr(server, "mask_error_text", lambda text: text)

    async def failing() -> None:
        raise ToolError(message)

    assert MARKER in await _client_error(monkeypatch, failing)


@pytest.mark.parametrize(
    "message",
    [
        'password=["unclosed", "' + MARKER,
        'password={"broken": [' + MARKER,
        'password=["mismatched"}, "' + MARKER + '"]',
        'password=["escaped ' + chr(92) + '" ] first", "' + MARKER,
    ],
)
async def test_ambiguous_credential_containers_fail_closed(monkeypatch, message):
    _install(monkeypatch)

    async def failing() -> None:
        raise ToolError(message)

    text = await _client_error(monkeypatch, failing)
    assert MARKER not in text
    assert REDACTION_MASK in text


@pytest.mark.parametrize("upstream", ["direct", "string", "exception"])
@pytest.mark.parametrize("enabled", [False, True], ids=["disabled", "enabled"])
@pytest.mark.parametrize("surround", [False, True], ids=["bare", "prose-quotes"])
@pytest.mark.parametrize(
    "form",
    ["prose-quoted-repr", "repr-json", "double-json", "set-dict"],
)
async def test_complete_representation_boundaries(monkeypatch, upstream, enabled, surround, form):
    """Prose quotes and invalid outer literals cannot split a credential list."""
    _install(monkeypatch, redact=enabled)
    row = {"password": ['a" ] }', MARKER], "id": "KEEP_ID", "reason": "KEEP_REASON"}
    messages = {
        "prose-quoted-repr": 'controller said "' + repr(row) + '"',
        "repr-json": repr(json.dumps(row)),
        "double-json": json.dumps(json.dumps(row)),
        "set-dict": "bad {" + json.dumps(row) + "}",
    }
    message = messages[form]
    if surround:
        message = 'controller said "' + message + '"'

    async def failing() -> None:
        if upstream == "exception":
            rendered = upstream_error_text(ValueError(message))
        elif upstream == "string":
            rendered = upstream_error_text(message)
        else:
            rendered = message
        raise ToolError(rendered)

    text = await _client_error(monkeypatch, failing)
    if not enabled:
        assert text == message
        return
    assert MARKER not in text
    assert 'a" ] }' not in text
    assert REDACTION_MASK in text
    assert "KEEP_ID" in text
    assert "KEEP_REASON" in text
    assert mask_error_text(text) == text


@pytest.mark.parametrize("value", [[MARKER], {"id": MARKER}, [{"token": MARKER}, MARKER]])
def test_pair_masks_a_complete_credential_container(value):
    message = "password=" + repr(value) + "; id=KEEP_ID; reason=KEEP_REASON"
    masked = mask_error_text(message)
    assert masked == REDACTION_MASK
    assert mask_error_text(masked) == masked


def _nested_fail_closed_corpus(max_depth=8):
    rows = [
        {"password": value, "id": "KEEP_ID", "reason": "KEEP_REASON"}
        for value in (*PARSER_VALUES, ['a" ] }', MARKER])
    ]
    for row in rows:
        for encoder in (repr, json.dumps):
            rendered = encoder(row)
            for depth in range(1, max_depth + 1):
                for wrapper in (
                    lambda text: text,
                    lambda text: 'controller said "' + text + '"',
                    lambda text: text + "}",
                ):
                    yield depth, wrapper(rendered)
                rendered = encoder(rendered)


@pytest.mark.parametrize("upstream", [False, True])
async def test_nested_fail_closed_corpus_real_client(monkeypatch, upstream):
    """All earlier values, both encoders, prose and trailing garbage, to depth 8."""
    client = _install(monkeypatch)
    for depth, message in _nested_fail_closed_corpus():

        async def failing(message=message) -> None:
            text = upstream_error_text(ValueError(message), client) if upstream else message
            raise ToolError(text)

        text = await _client_error(monkeypatch, failing)
        assert MARKER not in text, message
        assert REDACTION_MASK in text
        if depth == 1:
            assert "KEEP_ID" in text, message
            assert "KEEP_REASON" in text, message


async def test_nested_fail_closed_corpus_negative_control(monkeypatch):
    _install(monkeypatch, redact=False)
    for depth, message in _nested_fail_closed_corpus(max_depth=6):

        async def failing(message=message) -> None:
            raise ToolError(message)

        text = await _client_error(monkeypatch, failing)
        assert MARKER in text, (depth, len(message), len(text), text[:100])


@pytest.mark.parametrize("helper", ["_mask_embedded_json", "_unescape_key"])
def test_masker_never_raises_on_parser_failure(monkeypatch, helper):
    from unifi_fabric import redaction

    def broken(*args, **kwargs):
        raise RuntimeError("synthetic parser failure")

    monkeypatch.setattr(redaction, helper, broken)
    message = "pass" + BACKSLASH + 'u0077ord="' + MARKER + '"'
    assert MARKER not in redaction.mask_error_text(message)


@pytest.mark.parametrize("key", ["acctServerSecret", "radius_macacl_empty_password"])
@pytest.mark.parametrize("value", [False, 12, None, {}, []])
def test_fail_closed_guard_uses_shared_type_rules(key, value):
    message = json.dumps({key: value, "id": "KEEP_ID"})
    assert mask_error_text(message) == message


@pytest.mark.parametrize("prefix", ["b", "r", "u", "br", "rb", "f", "rf", "fr", "BR", "Rf"])
@pytest.mark.parametrize("upstream", [False, True])
async def test_prefixed_literal_values_real_client(monkeypatch, prefix, upstream):
    client = _install(monkeypatch)
    message = f"password={prefix}'first {MARKER}'; id=KEEP_ID"

    async def failing() -> None:
        text = upstream_error_text(ValueError(message), client) if upstream else message
        raise ToolError(text)

    text = await _client_error(monkeypatch, failing)
    assert text == REDACTION_MASK
    assert mask_error_text(text) == text


@pytest.mark.parametrize(
    "value",
    [
        "first " + MARKER,
        "b'first " + chr(92) + "'escaped " + MARKER + "'",
        "r'unclosed " + MARKER,
    ],
)
def test_pair_masks_complete_bare_or_prefixed_value(value):
    masked = mask_error_text("password=" + value + "; id=KEEP_ID")
    assert MARKER not in masked
    assert REDACTION_MASK in masked


@pytest.mark.parametrize("quote", ["'''", '"""'])
@pytest.mark.parametrize("upstream", [False, True])
async def test_triple_quoted_values_fail_closed_real_client(monkeypatch, quote, upstream):
    client = _install(monkeypatch)
    message = f"failure before password={quote}first {MARKER}{quote}; id=KEEP_ID"

    async def failing() -> None:
        text = upstream_error_text(ValueError(message), client) if upstream else message
        raise ToolError(text)

    text = await _client_error(monkeypatch, failing)
    assert text == "failure before " + REDACTION_MASK
    assert MARKER not in text
    assert mask_error_text(text) == text


def test_escaped_key_before_plain_key_fails_closed_at_first_key():
    message = "before pass\\u0077ord=first-secret; token=second-secret"
    assert mask_error_text(message) == "before " + REDACTION_MASK


# Every depth is delivered both directly and through the upstream formatter.
DEEP_ESCAPE_CORPUS = [
    "pass" + BACKSLASH * count + "u0077ord=SYNTHETIC_REVIEW_MARKER id=KEEP_ID"
    for count in (1, 2, 8, 32, 64)
]


@pytest.mark.parametrize("message", DEEP_ESCAPE_CORPUS)
@pytest.mark.parametrize("upstream", [False, True])
async def test_deep_escape_corpus_real_client(monkeypatch, message, upstream):
    client = _install(monkeypatch)

    async def failing() -> None:
        text = upstream_error_text(ValueError(message), client) if upstream else message
        raise ToolError(text)

    text = await _client_error(monkeypatch, failing)
    assert "SYNTHETIC_REVIEW_MARKER" not in text
    assert REDACTION_MASK in text
    assert "KEEP_ID" not in text
    assert mask_error_text(text) == text


@pytest.mark.parametrize("layers", [127, 128, 129, 130])
@pytest.mark.parametrize("upstream", [False, True])
async def test_escape_iteration_boundary_real_client(monkeypatch, layers, upstream):
    client = _install(monkeypatch)
    # Each u005c introduces exactly one more decode before the w appears.
    message = "pass" + BACKSLASH + "u005c" * (layers - 1) + "u0077ord=" + MARKER

    async def failing() -> None:
        text = upstream_error_text(ValueError(message), client) if upstream else message
        raise ToolError(text)

    text = await _client_error(monkeypatch, failing)
    assert MARKER not in text
    if layers <= 128:
        assert REDACTION_MASK in text
    else:
        assert "upstream error withheld" in text
    assert mask_error_text(text) == text


def test_intermediate_decoded_non_key_is_preserved():
    # The credential word is never immediately followed by a key separator.
    # Rule B preserves it even at an intermediate escape level.
    message = "prefix: pass" + BACKSLASH + "u0077ord" + BACKSLASH + "u005cq=" + MARKER
    assert mask_error_text(message) == message


# Four reviewer shapes, delivered through both error paths: eight probes.
REVIEW_DESCENDANTS = [
    repr({"body": ("password=" + MARKER).encode()}),
    repr({"body": {"password=" + MARKER}}),
    json.dumps({"body": repr({"body": ("password=" + MARKER).encode()})}),
    json.dumps({"body": repr({"body": {"password=" + MARKER}})}),
]


@pytest.mark.parametrize("message", REVIEW_DESCENDANTS)
@pytest.mark.parametrize("upstream", [False, True])
async def test_nested_bytes_sets_real_client(monkeypatch, message, upstream):
    client = _install(monkeypatch)

    async def failing() -> None:
        text = upstream_error_text(ValueError(message), client) if upstream else message
        raise ToolError(text)

    text = await _client_error(monkeypatch, failing)
    assert MARKER not in text
    assert REDACTION_MASK in text
    assert mask_error_text(text) == text


@pytest.mark.parametrize("upstream", [False, True])
async def test_password_tool_name_refusal_real_client(monkeypatch, upstream):
    client = _install(monkeypatch)
    message = (
        "Error calling tool 'update_protect_device_password': "
        "all fields held the redaction mask; password_policy_tool refused the write"
    )

    async def failing() -> None:
        text = upstream_error_text(ValueError(message), client) if upstream else message
        raise ToolError(text)

    assert await _client_error(monkeypatch, failing) == message


@pytest.mark.parametrize("wrapped", [False, True])
@pytest.mark.parametrize("upstream", [False, True])
async def test_incomplete_tool_header_masks_credential_real_client(monkeypatch, wrapped, upstream):
    client = _install(monkeypatch)
    message = "Error calling tool 'password=" + MARKER
    if wrapped:
        message = json.dumps({"body": message})

    async def failing() -> None:
        text = upstream_error_text(ValueError(message), client) if upstream else message
        raise ToolError(text)

    text = await _client_error(monkeypatch, failing)
    assert MARKER not in text
    assert REDACTION_MASK in text
    assert mask_error_text(text) == text


@pytest.mark.parametrize(
    "encode",
    [
        json.dumps,
        repr,
        lambda row: "; ".join(f"{key}={value!r}" for key, value in row.items()),
        lambda row: "; ".join(f"{key}={json.dumps(value)}" for key, value in row.items()),
    ],
    ids=["json", "repr", "single-quoted-pair", "double-quoted-pair"],
)
@pytest.mark.parametrize("key", ["secret", "password", "radius_secret"])
@pytest.mark.parametrize("upstream", [False, True])
async def test_empty_credential_preserves_diagnostics_real_client(
    monkeypatch, encode, key, upstream
):
    client = _install(monkeypatch)
    message = encode({key: "", "id": "KEEP_ID", "reason": "KEEP_REASON"})

    async def failing() -> None:
        text = upstream_error_text(ValueError(message), client) if upstream else message
        raise ToolError(text)

    text = await _client_error(monkeypatch, failing)
    assert "KEEP_ID" in text
    assert "KEEP_REASON" in text
    assert mask_error_text(text) == text


@pytest.mark.parametrize("prefix", ["'", " ", "-", "+", "$", "/", ".", "@"])
def test_credential_assignment_after_nonword_boundary(prefix):
    message = "outer" + prefix + "password=" + MARKER
    assert MARKER not in mask_error_text(message)


@pytest.mark.parametrize("name", ["password", "update_protect_device_password"])
def test_complete_credential_named_tool_header_is_preserved(name):
    message = f"Error calling tool '{name}': password is wrong"
    assert mask_error_text(message) == message
