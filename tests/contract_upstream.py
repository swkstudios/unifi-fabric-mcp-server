"""The contract-fixture upstream: the ``input.upstream`` block of a fixture envelope.

``input.upstream`` maps a credential label to the consoles that credential's
``GET /v1/hosts`` lists (``status`` ``ok``), or to a failing list (``list_failed``: HTTP
500; ``page_cap``: every page carries a ``nextToken``). Every other request answers
``200 {"data": []}``. Each request is recorded with the label of the credential that
sent it, so a runner can assert ``upstream_calls``, ``upstream_mutations`` and
``selected_labels`` (the labels that reached the upstream, in first-call order).

The client is the real ``UniFiClient``: only ``_new_http_client`` is replaced, so the
environment-mode client cache and the header-mode credential cache stay in the path.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import httpx

from unifi_fabric.client import UniFiClient, is_write_request
from unifi_fabric.config import APIKeyConfig

#: The production ``_get_client``, captured before any test patches it (the request-policy
#: fixture runner restores it over ``upstream_harness.install``'s replacement).
REAL_GET_CLIENT = UniFiClient.__dict__["_get_client"]
STATUSES = ("ok", "list_failed", "page_cap")


@dataclass
class Call:
    label: str
    method: str
    path: str
    body: Any


@dataclass
class ContractUpstream:
    spec: dict[str, dict[str, Any]]
    calls: list[Call] = field(default_factory=list)

    def __post_init__(self) -> None:
        for label, entry in self.spec.items():
            assert entry["status"] in STATUSES, (label, entry["status"])

    def handler(self, label: str, request: httpx.Request) -> httpx.Response:
        body: Any = None
        if request.content:
            try:
                body = httpx.Response(200, content=request.content).json()
            except ValueError:
                body = request.content.decode(errors="replace")
        self.calls.append(Call(label, request.method, request.url.path, body))
        if request.method == "GET" and request.url.path == "/v1/hosts":
            entry = self.spec.get(label)
            if entry is None:
                return httpx.Response(200, json={"data": []}, request=request)
            if entry["status"] == "list_failed":
                return httpx.Response(500, json={"message": "list failed"}, request=request)
            page: dict[str, Any] = {"data": [dict(c) for c in entry["consoles"]]}
            if entry["status"] == "page_cap":
                page["nextToken"] = f"page-{len(self.calls)}"
            return httpx.Response(200, json=page, request=request)
        return httpx.Response(200, json={"data": []}, request=request)

    def mutations(self) -> list[Call]:
        return [c for c in self.calls if is_write_request(c.method, c.path, c.body)]

    def labels(self) -> list[str]:
        """The credential labels that reached the upstream, in first-call order."""
        seen: list[str] = []
        for call in self.calls:
            if call.label not in seen:
                seen.append(call.label)
        return seen


def install(monkeypatch: Any, spec: dict[str, dict[str, Any]] | None) -> ContractUpstream:
    """Serve every real ``UniFiClient`` from ``spec`` (no spec: every label lists nothing)."""
    upstream = ContractUpstream(dict(spec or {}))

    def factory(self: UniFiClient, key_config: APIKeyConfig) -> httpx.AsyncClient:
        label = key_config.label
        return httpx.AsyncClient(
            base_url=self._settings.api_base_url,
            headers={"X-API-KEY": key_config.key, "Accept": "application/json"},
            transport=httpx.MockTransport(lambda request: upstream.handler(label, request)),
        )

    monkeypatch.setattr(UniFiClient, "_new_http_client", factory)
    return upstream
