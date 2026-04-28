"""G5: verify password is best-effort cleared from config after a successful
login, and that re-login attempts after the drop fail with a clear error
rather than crashing or sending an empty password."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from unittest.mock import MagicMock, patch

import pytest

from spl_bridge.auth import (
    SplunkLoginError,
    login_with_password,
    reset_session,
)
from spl_bridge.config import SplunkMCPConfig


@pytest.fixture(autouse=True)
def _reset() -> None:
    reset_session()
    yield
    reset_session()


def _ok_response() -> MagicMock:
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"sessionKey": "session-abc"}
    return r


class TestPasswordDropped:
    def test_password_cleared_after_successful_login(self) -> None:
        cfg = SplunkMCPConfig(host="h", username="admin", password="hunter2")
        with patch("spl_bridge.auth.requests.post", return_value=_ok_response()):
            sk = login_with_password(cfg)
        assert sk == "session-abc"
        assert cfg.password is None

    def test_relogin_after_drop_raises_clear_error(self) -> None:
        cfg = SplunkMCPConfig(host="h", username="admin", password="hunter2")
        with patch("spl_bridge.auth.requests.post", return_value=_ok_response()):
            login_with_password(cfg)

        # Now password is gone - simulate a re-auth attempt.
        with pytest.raises(SplunkLoginError, match="restart"):
            login_with_password(cfg)

    def test_password_drop_does_not_break_token_mode(self) -> None:
        # Token mode never enters login_with_password; sanity-check that
        # the dataclass allows setattr only via object.__setattr__.
        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        # Frozen dataclass - normal assignment must still fail.
        # `dataclasses.FrozenInstanceError` is the documented type, but
        # we accept any AttributeError-derived raise to stay tolerant
        # of alternative dataclass implementations on older runtimes.
        with pytest.raises((AttributeError, FrozenInstanceError)):
            cfg.password = "x"  # type: ignore[misc]
