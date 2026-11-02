"""Server boundaries and tool descriptions."""

from unittest.mock import AsyncMock

import pytest

from unifi_fabric import server
from unifi_fabric.client import UniFiConnectionError
from unifi_fabric.tools import carrier_fabric


@pytest.mark.parametrize("failure", ["alpha", "both", "none"])
@pytest.mark.parametrize("with_null", [False, True])
async def test_isp_site_resolution_is_per_key(
    multikey_client, multikey_registry, monkeypatch, failure, with_null
):
    client, registry = multikey_client, multikey_registry
    monkeypatch.setattr(server, "_require", lambda: (client, registry))

    async def owner(host):
        return client.get_key_by_label(host)

    async def host_id(host, *, key):
        return host

    async def site_id(site, *, host_id, key):
        if failure == "both" or key.label == failure:
            raise UniFiConnectionError("GET /v1/sites HTTP 500: unavailable")
        return site

    post = AsyncMock(return_value={"data": {"metrics": [{"periods": []}]}})
    monkeypatch.setattr(registry, "resolve_key_for_host", owner)
    monkeypatch.setattr(registry, "resolve_host_id", host_id)
    monkeypatch.setattr(registry, "resolve_ea_site_id", site_id)
    monkeypatch.setattr(client, "post", post)
    entries = [{"hostId": "alpha", "siteId": "sa"}, {"hostId": "beta", "siteId": "sb"}]
    if with_null:
        entries.insert(1, None)
    if failure == "both":
        with pytest.raises(RuntimeError, match="All 2 API keys failed"):
            await server.query_isp_metrics("5m", sites=entries)
        post.assert_not_awaited()
        return
    result = await server.query_isp_metrics("5m", sites=entries)
    assert result["_key_labels"] == (["beta"] if failure == "alpha" else ["alpha", "beta"])
    if failure == "alpha":
        assert "alpha: GET /v1/sites HTTP 500" in result["errors"][0]
    for call in post.await_args_list:
        sent = call.kwargs["json"]["sites"]
        label = call.kwargs["key"].label
        assert (None in sent) == with_null
        assert [x["hostId"] for x in sent if x is not None] == [label]


async def test_isp_invalid_selector_before_resolution(
    multikey_client, multikey_registry, monkeypatch
):
    monkeypatch.setattr(server, "_require", lambda: (multikey_client, multikey_registry))
    owner = AsyncMock()
    monkeypatch.setattr(multikey_registry, "resolve_key_for_host", owner)
    with pytest.raises(ValueError):
        await server.query_isp_metrics(
            "5m", sites=[{"hostId": "alpha", "siteId": "sa"}, {"hostId": "beta", "siteId": " "}]
        )
    owner.assert_not_awaited()


@pytest.mark.parametrize(
    "field", ["name", "email", "notes", "service_address", "plan_id", "metadata"]
)
@pytest.mark.parametrize("explicit_null", [True, False])
async def test_carrier_tool_distinguishes_null_from_omission(monkeypatch, field, explicit_null):
    monkeypatch.setattr(server, "_require", lambda: (object(), object()))
    update = AsyncMock(return_value={"status": "updated"})
    monkeypatch.setattr(carrier_fabric, "update_carrier_subscriber", update)
    await server.update_carrier_subscriber(
        "11111111-1111-4111-8111-111111111111", **({field: None} if explicit_null else {})
    )
    kwargs = update.await_args.kwargs
    assert (field in kwargs) == explicit_null
    if explicit_null:
        assert kwargs[field] is None


@pytest.mark.parametrize("verb", ["get", "post", "put", "patch", "delete"])
def test_relay_descriptions_cover_unclassified_routes(verb):
    description = getattr(server, "fabric_connector_" + verb).__doc__
    assert "unclassified" in description
    assert "Only UniFi application namespaces are allowed" not in description
    assert "Allowed roots:" not in description
    assert "GET" in description and "opt-out" in description


def test_carrier_update_description_matches_explicit_null():
    description = server.update_carrier_subscriber.__doc__
    assert "Omitting a field (None)" not in description
    assert "clear it with clear_fields" not in description
    assert "metadata=null" in description


EXPLICIT_PAGE_DOCS = {
    # A bare-list page carries no _warnings; an object page keeps its upstream fields and
    # carries the drained result's _warnings.
    "list_protect_events": (
        "An explicit offset/limit fetches one page",
        "a bare list stays a list (without warnings)",
        "an object page preserves every upstream top-level field verbatim",
        "Object pages carry epoch-unit and smart-detect _warnings, as drained results do",
    ),
    "list_recognition_detections": (
        "An explicit page keeps a bare list verbatim (no _warnings)",
        "preserves every field of an object page verbatim",
        "epoch-unit _warnings",
    ),
}


@pytest.mark.parametrize("name", sorted(EXPLICIT_PAGE_DOCS))
def test_server_explicit_page_warning_exception_is_documented(name):
    description = " ".join(getattr(server, name).__doc__.split())
    for phrase in EXPLICIT_PAGE_DOCS[name]:
        assert phrase in description, phrase
