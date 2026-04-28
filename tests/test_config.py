"""Tests for spl_bridge.config."""

from __future__ import annotations

import pytest

from spl_bridge.config import SplunkMCPConfig


def _clean_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in (
        "SPLUNK_HOST",
        "SPLUNK_PORT",
        "SPLUNK_SCHEME",
        "SPLUNK_VERIFY_SSL",
        "SPLUNK_TOKEN",
        "SPLUNK_USERNAME",
        "SPLUNK_PASSWORD",
        "SPLUNK_APP",
        "MCP_TIMEOUT",
        "MCP_MAX_ROW_LIMIT",
        "MCP_DEFAULT_ROW_LIMIT",
        "SPLUNK_ALLOW_PLAINTEXT",
        "MCP_RATE_LIMITS",
    ):
        monkeypatch.delenv(key, raising=False)


class TestFromEnv:
    def test_token_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "splunk.local")
        monkeypatch.setenv("SPLUNK_TOKEN", "abc123")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.host == "splunk.local"
        assert cfg.auth_mode == "token"
        assert cfg.splunk_token == "abc123"

    def test_password_mode(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "lab.local")
        monkeypatch.setenv("SPLUNK_USERNAME", "admin")
        monkeypatch.setenv("SPLUNK_PASSWORD", "changeme")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.auth_mode == "password"

    def test_missing_host_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_TOKEN", "tok")
        with pytest.raises(EnvironmentError, match="SPLUNK_HOST"):
            SplunkMCPConfig.from_env()

    def test_missing_auth_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        with pytest.raises(EnvironmentError, match="SPLUNK_TOKEN"):
            SplunkMCPConfig.from_env()

    def test_token_precedence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "tok")
        monkeypatch.setenv("SPLUNK_USERNAME", "admin")
        monkeypatch.setenv("SPLUNK_PASSWORD", "pass")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.auth_mode == "token"

    def test_custom_limits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "tok")
        monkeypatch.setenv("MCP_MAX_ROW_LIMIT", "500")
        monkeypatch.setenv("MCP_DEFAULT_ROW_LIMIT", "50")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.max_row_limit == 500
        assert cfg.default_row_limit == 50

    def test_ssl_verify_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "tok")
        monkeypatch.setenv("SPLUNK_VERIFY_SSL", "false")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.ssl_verify is False

    def test_base_url(self) -> None:
        cfg = SplunkMCPConfig(host="splunk.co", port=8089, scheme="https", splunk_token="t")
        assert cfg.base_url == "https://splunk.co:8089"

    def test_services_prefix_with_app(self) -> None:
        cfg = SplunkMCPConfig(host="h", splunk_token="t", app="search")
        assert cfg.services_prefix() == "/servicesNS/-/search"

    def test_services_prefix_without_app(self) -> None:
        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        assert cfg.services_prefix() == "/services"


class TestPlaintextHttpGate:
    """L-4: HTTP scheme + token requires explicit opt-in."""

    def test_token_over_http_without_optin_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_SCHEME", "http")
        monkeypatch.setenv("SPLUNK_TOKEN", "tok")
        with pytest.raises(ValueError, match="SPLUNK_ALLOW_PLAINTEXT"):
            SplunkMCPConfig.from_env()

    def test_token_over_http_with_optin_succeeds_with_warning(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_SCHEME", "http")
        monkeypatch.setenv("SPLUNK_TOKEN", "tok")
        monkeypatch.setenv("SPLUNK_ALLOW_PLAINTEXT", "1")
        warnings: list[str] = []
        from spl_bridge import config as cfg_mod

        monkeypatch.setattr(
            cfg_mod.logger, "warning", lambda msg, *a, **kw: warnings.append(msg % a if a else msg)
        )
        cfg = SplunkMCPConfig.from_env()
        assert cfg.scheme == "http"
        assert cfg.splunk_token == "tok"
        assert any("SPLUNK_SCHEME=http" in w for w in warnings)

    def test_password_over_http_emits_warning_no_block(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        # Wizard blocks this end-to-end; the config layer warns but does
        # not raise (operator may still have a closed lab use case).
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_SCHEME", "http")
        monkeypatch.setenv("SPLUNK_USERNAME", "u")
        monkeypatch.setenv("SPLUNK_PASSWORD", "p")
        warnings: list[str] = []
        from spl_bridge import config as cfg_mod

        monkeypatch.setattr(
            cfg_mod.logger, "warning", lambda msg, *a, **kw: warnings.append(msg % a if a else msg)
        )
        cfg = SplunkMCPConfig.from_env()
        assert cfg.auth_mode == "password"
        assert any("SPLUNK_SCHEME=http" in w for w in warnings)

    def test_https_path_does_not_require_optin(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_SCHEME", "https")
        monkeypatch.setenv("SPLUNK_TOKEN", "tok")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.scheme == "https"


class TestRateLimitBounds:
    """L-5: bound MCP_RATE_LIMITS integer values."""

    def test_negative_value_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_RATE_LIMITS", '{"global": -5}')
        with pytest.raises(ValueError, match="rate limit"):
            SplunkMCPConfig.from_env()

    def test_oversized_value_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_RATE_LIMITS", '{"global": 99999999999}')
        with pytest.raises(ValueError, match="rate limit"):
            SplunkMCPConfig.from_env()

    def test_zero_is_valid_always_deny(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_RATE_LIMITS", '{"global": 0}')
        cfg = SplunkMCPConfig.from_env()
        assert cfg.rate_limits == {"global": 0}

    def test_in_range_value_kept(self, monkeypatch: pytest.MonkeyPatch) -> None:
        _clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_RATE_LIMITS", '{"global": 1000, "search": 50}')
        cfg = SplunkMCPConfig.from_env()
        assert cfg.rate_limits == {"global": 1000, "search": 50}
