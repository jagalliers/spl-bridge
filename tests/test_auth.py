"""Tests for spl_bridge.auth."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from spl_bridge.auth import (
    _token_authorization_value,
    get_auth_header,
    login_with_password,
    reset_session,
)
from spl_bridge.config import SplunkMCPConfig


class TestTokenAuthorizationValue:
    def test_jwt_gets_bearer(self) -> None:
        assert _token_authorization_value("eyJhbGciOiJSUzI1NiJ9.xxx.yyy").startswith("Bearer ")

    def test_session_key_gets_splunk(self) -> None:
        assert _token_authorization_value("abc123opaque").startswith("Splunk ")


class TestLoginWithPassword:
    def test_returns_session_key(self) -> None:
        cfg = SplunkMCPConfig(host="lab.local", username="admin", password="changeme")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sessionKey": "sess_abc"}
        mock_resp.raise_for_status = MagicMock()

        with patch("spl_bridge.auth.requests.post", return_value=mock_resp):
            key = login_with_password(cfg)
        assert key == "sess_abc"

    def test_missing_session_key_raises(self) -> None:
        cfg = SplunkMCPConfig(host="lab.local", username="admin", password="p")
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {}
        mock_resp.raise_for_status = MagicMock()

        with patch("spl_bridge.auth.requests.post", return_value=mock_resp):
            with pytest.raises(RuntimeError, match="sessionKey"):
                login_with_password(cfg)


class TestGetAuthHeader:
    def test_token_mode(self) -> None:
        reset_session()
        cfg = SplunkMCPConfig(host="h", splunk_token="mytoken123")
        header = get_auth_header(cfg)
        assert header == "Splunk mytoken123"

    def test_password_mode_calls_login(self) -> None:
        reset_session()
        cfg = SplunkMCPConfig(host="h", username="admin", password="pass")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sessionKey": "sk_123"}
        mock_resp.raise_for_status = MagicMock()

        with patch("spl_bridge.auth.requests.post", return_value=mock_resp):
            header = get_auth_header(cfg)
        assert header == "Splunk sk_123"

    def test_password_mode_caches(self) -> None:
        reset_session()
        cfg = SplunkMCPConfig(host="h", username="admin", password="pass")

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"sessionKey": "cached_key"}
        mock_resp.raise_for_status = MagicMock()

        with patch("spl_bridge.auth.requests.post", return_value=mock_resp) as mock_post:
            get_auth_header(cfg)
            get_auth_header(cfg)
            assert mock_post.call_count == 1
