"""Tests for UNIFI_LOG_LEVEL env var — controllable server logging."""

from __future__ import annotations

import importlib
import logging


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
    def test_server_applies_log_level_to_root_logger(self, monkeypatch):
        """After reload, root logger effective level matches UNIFI_LOG_LEVEL."""
        monkeypatch.setenv("UNIFI_LOG_LEVEL", "DEBUG")
        monkeypatch.setenv("UNIFI_API_KEY", "sk-test-log-level")
        # Reset root logger handlers so basicConfig isn't a no-op
        root = logging.getLogger()
        original_handlers = root.handlers[:]
        root.handlers = []
        try:
            import unifi_fabric.server as srv

            importlib.reload(srv)
            assert root.level == logging.DEBUG
        finally:
            root.handlers = original_handlers

    def test_server_default_log_level_is_info(self, monkeypatch):
        """Without UNIFI_LOG_LEVEL, root logger defaults to INFO."""
        monkeypatch.delenv("UNIFI_LOG_LEVEL", raising=False)
        monkeypatch.setenv("UNIFI_API_KEY", "sk-test-log-level")
        root = logging.getLogger()
        original_handlers = root.handlers[:]
        root.handlers = []
        try:
            import unifi_fabric.server as srv

            importlib.reload(srv)
            assert root.level == logging.INFO
        finally:
            root.handlers = original_handlers
