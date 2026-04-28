"""Tests for M6 (graceful shutdown) and M7 (assert no logging->stdout).

These guard the two stdio-transport invariants:

* ``server.main`` must always close the ``SplunkClient`` (releasing the
  ``requests.Session`` and any cached password-mode session key) even
  when the MCP runtime exits via an exception or KeyboardInterrupt.
* Before ``app.run`` we must verify no logging handler is wired to
  ``sys.stdout``; otherwise the JSON-RPC frame stream would be poisoned.
"""

from __future__ import annotations

import logging
import os
import sys
from unittest.mock import MagicMock

import pytest

from spl_bridge import server
from spl_bridge.logging_config import configure_logging

# ---------------------------------------------------------------------------
# M7 - _assert_no_logging_to_stdout
# ---------------------------------------------------------------------------


class TestAssertNoLoggingToStdout:
    """The startup guard must raise when a stray handler points at stdout."""

    def setup_method(self) -> None:
        # Snapshot existing handlers so we can restore them.
        self._prev_root_handlers = list(logging.getLogger().handlers)
        configure_logging(stream=sys.stderr)

    def teardown_method(self) -> None:
        logging.getLogger().handlers = self._prev_root_handlers
        os.environ.pop("SPLUNK_MCP_ALLOW_STDOUT_LOGGING", None)

    def test_clean_state_passes(self) -> None:
        # Default configure_logging() targets stderr; should not raise.
        server._assert_no_logging_to_stdout()

    def test_root_handler_on_stdout_rejected(self) -> None:
        bad = logging.StreamHandler(sys.stdout)
        logging.getLogger().addHandler(bad)
        try:
            with pytest.raises(RuntimeError, match="stdout"):
                server._assert_no_logging_to_stdout()
        finally:
            logging.getLogger().removeHandler(bad)

    def test_named_logger_handler_on_stdout_rejected(self) -> None:
        log = logging.getLogger("test_m7_named_logger")
        bad = logging.StreamHandler(sys.stdout)
        log.addHandler(bad)
        try:
            with pytest.raises(RuntimeError, match="stdout"):
                server._assert_no_logging_to_stdout()
        finally:
            log.removeHandler(bad)

    def test_opt_out_env_var(self, monkeypatch: pytest.MonkeyPatch) -> None:
        bad = logging.StreamHandler(sys.stdout)
        logging.getLogger().addHandler(bad)
        monkeypatch.setenv("SPLUNK_MCP_ALLOW_STDOUT_LOGGING", "1")
        try:
            # Must NOT raise when the opt-out is set.
            server._assert_no_logging_to_stdout()
        finally:
            logging.getLogger().removeHandler(bad)


# ---------------------------------------------------------------------------
# M6 - main() always calls client.close()
# ---------------------------------------------------------------------------


class _FakeApp:
    """Fake FastMCP app: ``run`` either returns or raises on cue."""

    def __init__(self, raise_exc: BaseException | None = None) -> None:
        self.raise_exc = raise_exc
        self.run_called = False

    def run(self, transport: str = "stdio") -> None:  # noqa: ARG002
        self.run_called = True
        if self.raise_exc is not None:
            raise self.raise_exc


@pytest.fixture()
def fake_config(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    cfg = MagicMock()
    cfg.host = "splunk.example"
    cfg.port = 8089
    cfg.auth_mode = "token"
    monkeypatch.setattr(server.SplunkMCPConfig, "from_env", classmethod(lambda cls: cfg))
    return cfg


@pytest.fixture()
def fake_client(monkeypatch: pytest.MonkeyPatch) -> MagicMock:
    inst = MagicMock(name="FakeSplunkClient")
    monkeypatch.setattr(server, "SplunkClient", lambda config: inst)
    return inst


class TestMainGracefulShutdown:
    def setup_method(self) -> None:
        self._prev_root_handlers = list(logging.getLogger().handlers)

    def teardown_method(self) -> None:
        logging.getLogger().handlers = self._prev_root_handlers

    def test_close_called_on_clean_exit(
        self,
        fake_config: MagicMock,
        fake_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        app = _FakeApp()
        monkeypatch.setattr(server, "_build_mcp_app", lambda c, cl: app)

        server.main()

        assert app.run_called
        fake_client.close.assert_called_once()

    def test_close_called_on_keyboard_interrupt(
        self,
        fake_config: MagicMock,
        fake_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        app = _FakeApp(raise_exc=KeyboardInterrupt())
        monkeypatch.setattr(server, "_build_mcp_app", lambda c, cl: app)

        # KeyboardInterrupt must NOT propagate (handled).
        server.main()

        fake_client.close.assert_called_once()

    def test_close_called_on_unexpected_exception(
        self,
        fake_config: MagicMock,
        fake_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        app = _FakeApp(raise_exc=RuntimeError("boom"))
        monkeypatch.setattr(server, "_build_mcp_app", lambda c, cl: app)

        with pytest.raises(RuntimeError, match="boom"):
            server.main()

        fake_client.close.assert_called_once()

    def test_close_error_does_not_mask_original(
        self,
        fake_config: MagicMock,
        fake_client: MagicMock,
        monkeypatch: pytest.MonkeyPatch,
    ) -> None:
        app = _FakeApp(raise_exc=RuntimeError("primary"))
        monkeypatch.setattr(server, "_build_mcp_app", lambda c, cl: app)
        fake_client.close.side_effect = OSError("close failed")

        with pytest.raises(RuntimeError, match="primary"):
            server.main()

        fake_client.close.assert_called_once()
