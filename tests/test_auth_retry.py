"""Verify session re-authentication on 401/403 (G4)."""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from spl_bridge import auth
from spl_bridge.config import SplunkMCPConfig
from spl_bridge.splunk_client import SplunkClient


def _resp(status: int, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    return r


@contextmanager
def _patch_http_request(*, side_effect=None, return_value=None):
    """Patch the module-level ``requests.request`` SplunkClient now uses.

    The earlier helper patched ``client._session.request``; that
    attribute no longer exists since SplunkClient mirrors
    Splunk_MCP_Server's per-call ``requests.request(...)`` shape.
    """
    kw = {}
    if side_effect is not None:
        kw["side_effect"] = side_effect
    if return_value is not None:
        kw["return_value"] = return_value
    with patch("spl_bridge.splunk_client.requests.request", **kw) as m:
        yield m


@pytest.fixture(autouse=True)
def _reset_session():
    auth.reset_session()
    yield
    auth.reset_session()


class TestPasswordModeReauth:
    def test_401_triggers_one_retry_then_succeeds(self) -> None:
        cfg = SplunkMCPConfig(host="h", username="admin", password="pw")
        client = SplunkClient(cfg)

        # Pre-seed session so first request goes straight out (no login).
        auth._session_state["session_key"] = "expired-key"
        auth._session_state["username"] = "admin"

        responses = [_resp(401, "expired"), _resp(200, '{"ok": true}')]

        # Mock login_with_password used internally by get_auth_header
        # after invalidation
        with (
            _patch_http_request(side_effect=responses),
            patch(
                "spl_bridge.auth.login_with_password",
                return_value="fresh-key",
            ) as mock_login,
        ):
            out = client.call_api("GET", "services/server/info")

        assert out.status_code == 200
        # Login called exactly once during the retry path
        assert mock_login.call_count == 1

    def test_two_consecutive_401s_do_not_loop(self) -> None:
        cfg = SplunkMCPConfig(host="h", username="admin", password="pw")
        client = SplunkClient(cfg)
        auth._session_state["session_key"] = "expired-key"
        auth._session_state["username"] = "admin"

        responses = [_resp(401), _resp(401), _resp(200)]
        # If we looped, we'd consume the 200 and assert below would fail.

        with (
            _patch_http_request(side_effect=responses),
            patch(
                "spl_bridge.auth.login_with_password",
                return_value="fresh-key",
            ),
        ):
            out = client.call_api("GET", "services/server/info")

        assert out.status_code == 401

    def test_login_failure_during_retry_returns_synthetic_401(self) -> None:
        cfg = SplunkMCPConfig(host="h", username="admin", password="pw")
        client = SplunkClient(cfg)
        auth._session_state["session_key"] = "expired-key"
        auth._session_state["username"] = "admin"

        with (
            _patch_http_request(return_value=_resp(401)),
            patch(
                "spl_bridge.auth.login_with_password",
                side_effect=auth.SplunkLoginError("bad creds"),
            ),
        ):
            out = client.call_api("GET", "services/server/info")

        assert out.status_code == 401
        # The synthetic body should be sanitized (no leaked exception text)
        body = out.text
        assert "bad creds" not in body


class TestTokenModeNoRetry:
    def test_token_mode_does_not_retry_on_401(self) -> None:
        cfg = SplunkMCPConfig(host="h", splunk_token="t-abc")
        client = SplunkClient(cfg)

        with _patch_http_request(return_value=_resp(401)) as mock_req:
            out = client.call_api("GET", "services/server/info")

        assert out.status_code == 401
        assert mock_req.call_count == 1

    def test_token_invalid_logged_once_per_process(self, caplog) -> None:
        import logging

        # The `spl_bridge` logger is non-propagating (see
        # `spl_bridge/__init__.py`), so caplog's default root handler
        # never sees its records. Attach caplog's handler directly to
        # the target logger for this assertion.
        target = logging.getLogger("spl_bridge.splunk_client")
        target.addHandler(caplog.handler)
        caplog.set_level(logging.ERROR, logger="spl_bridge.splunk_client")
        try:
            cfg = SplunkMCPConfig(host="h", splunk_token="t-abc")
            client = SplunkClient(cfg)

            with _patch_http_request(return_value=_resp(401)):
                client.call_api("GET", "services/server/info")
                client.call_api("GET", "services/server/info")
                client.call_api("GET", "services/server/info")

            rejected = [r for r in caplog.records if "Splunk rejected token" in r.getMessage()]
            assert len(rejected) == 1
        finally:
            target.removeHandler(caplog.handler)
