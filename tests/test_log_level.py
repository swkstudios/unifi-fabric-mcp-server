"""Tests for UNIFI_LOG_LEVEL env var — controllable server logging."""

from __future__ import annotations

import importlib
import logging

import pytest


def _reload_server(monkeypatch, *, log_level: str = "INFO") -> None:
    """Reload config module with UNIFI_LOG_LEVEL set and return fresh Settings."""
    monkeypatch.setenv("UNIFI_LOG_LEVEL", log_level)
    monkeypatch.setenv("UNIFI_API_KEY", "sk-test-log-level")
    import unifi_fabric.config as cfg

    importlib.reload(cfg)
    return cfg


# ---------------------------------------------------------------------------
# Config layer
# ---------------------------------------------------------------------------


class TestLogLevelConfig:
    def test_defaults_to_info(self, monkeypatch):
        monkeypatch.delenv("UNIFI_LOG_LEVEL", raising=False)
        from unifi_fabric.config import Settings

        s = Settings()
        assert s.log_level == "INFO"

    def test_reads_debug_from_env(self, monkeypatch):
        monkeypatch.setenv("UNIFI_LOG_LEVEL", "DEBUG")
        from unifi_fabric.config import Settings

        s = Settings()
        assert s.log_level == "DEBUG"

    def test_reads_warning_from_env(self, monkeypatch):
        monkeypatch.setenv("UNIFI_LOG_LEVEL", "WARNING")
        from unifi_fabric.config import Settings

        s = Settings()
        assert s.log_level == "WARNING"

    def test_reads_error_from_env(self, monkeypatch):
        monkeypatch.setenv("UNIFI_LOG_LEVEL", "ERROR")
        from unifi_fabric.config import Settings

        s = Settings()
        assert s.log_level == "ERROR"

    def test_reads_critical_from_env(self, monkeypatch):
        monkeypatch.setenv("UNIFI_LOG_LEVEL", "CRITICAL")
        from unifi_fabric.config import Settings

        s = Settings()
        assert s.log_level == "CRITICAL"


# ---------------------------------------------------------------------------
# Server wiring — basicConfig uses the setting
# ---------------------------------------------------------------------------


class TestLogLevelServerWiring:
    """Logging is configured at server *startup* (lifespan), not at import.

    Importing the server module no longer has logging side effects — that was a
    module-scope side effect removed with the lazy get_settings() change. These
    tests drive lifespan() and assert the root logger picks up UNIFI_LOG_LEVEL.
    """

    @pytest.mark.asyncio
    async def test_server_applies_log_level_to_root_logger(self, monkeypatch):
        """lifespan() sets the root logger level from UNIFI_LOG_LEVEL."""
        monkeypatch.setenv("UNIFI_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("UNIFI_API_KEY", "sk-test-log-level")
        import unifi_fabric.server as srv

        root = logging.getLogger()
        original_handlers = root.handlers[:]
        original_level = root.level
        root.handlers = []
        try:
            async with srv.lifespan(None):
                assert root.level == logging.DEBUG
        finally:
            root.handlers = original_handlers
            root.setLevel(original_level)

    @pytest.mark.asyncio
    async def test_server_default_log_level_is_info(self, monkeypatch):
        """Without UNIFI_LOG_LEVEL, lifespan() defaults the root logger to INFO."""
        monkeypatch.delenv("UNIFI_LOG_LEVEL", raising=False)
        monkeypatch.setenv("UNIFI_API_KEY", "sk-test-log-level")
        import unifi_fabric.server as srv

        root = logging.getLogger()
        original_handlers = root.handlers[:]
        original_level = root.level
        root.handlers = []
        try:
            async with srv.lifespan(None):
                assert root.level == logging.INFO
        finally:
            root.handlers = original_handlers
            root.setLevel(original_level)
