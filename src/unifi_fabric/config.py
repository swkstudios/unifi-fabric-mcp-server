"""Configuration for UniFi Fabric MCP Server."""

from __future__ import annotations

from pydantic import Field
from pydantic_settings import BaseSettings


class APIKeyConfig(BaseSettings):
    """Configuration for a single UniFi Site Manager API key."""

    key: str
    label: str = "default"
    is_org_key: bool = Field(
        default=False,
        description="Organization keys cover all sites under the org. "
        "Personal keys only access consoles owned by the key holder.",
    )


class Settings(BaseSettings):
    """Top-level settings loaded from environment variables."""

    model_config = {"env_prefix": "UNIFI_", "env_nested_delimiter": "__"}

    api_base_url: str = Field(
        default="https://api.ui.com",
        description="UniFi Site Manager API base URL.",
    )
    api_keys: list[APIKeyConfig] = Field(
        default_factory=list,
        description="List of API key configs. Set via UNIFI_API_KEY for single key.",
    )
    api_key: str = Field(
        default="",
        description="Single API key shorthand. Used when api_keys is empty.",
    )
    cache_ttl_seconds: int = Field(
        default=900,
        description="TTL for host/site registry cache (default 15 min).",
    )
    cache_max_hosts: int = Field(
        default=512,
        description="Max entries in the hosts TTLCache (default 512).",
    )
    cache_max_sites: int = Field(
        default=2048,
        description="Max entries in the sites TTLCache (default 2048).",
    )
    max_concurrency: int = Field(
        default=10,
        description="Max concurrent requests for cross-site aggregation.",
    )
    request_timeout_seconds: int = Field(
        default=30,
        description="HTTP request timeout in seconds for UniFi API calls.",
    )
    paginate_max_pages: int | None = Field(
        default=None,
        description="Hard cap on pagination page count (defense-in-depth backstop). "
        "Unset by default — stall detection is the primary safeguard. "
        "Set UNIFI_PAGINATE_MAX_PAGES to a generous number (e.g. 100000) if desired.",
    )

    def get_key_configs(self) -> list[APIKeyConfig]:
        """Return resolved list of API key configs."""
        if self.api_keys:
            return self.api_keys
        if self.api_key:
            return [APIKeyConfig(key=self.api_key, label="default")]
        return []
