"""Verify the structured JSON formatter and context filter behavior, and
that the redaction deny-list (G8) prevents secrets from leaking via log
extras."""

from __future__ import annotations

import json
import logging

import pytest

from spl_bridge.logging_config import (
    _REDACT_KEYS,
    MCPContextFilter,
    MCPJsonFormatter,
    clear_log_context,
    current_request_id,
    set_request_id,
    update_log_context,
)


@pytest.fixture()
def jsonlog(caplog):
    """Capture log records and emit them through MCPJsonFormatter."""
    caplog.set_level(logging.INFO)
    fmt = MCPJsonFormatter()

    def _get_records() -> list[dict]:
        return [json.loads(fmt.format(r)) for r in caplog.records]

    yield _get_records


class TestRequestIdContext:
    def setup_method(self) -> None:
        clear_log_context()

    def teardown_method(self) -> None:
        clear_log_context()

    def test_set_and_get_request_id(self) -> None:
        rid = set_request_id()
        assert current_request_id() == rid
        assert len(rid) == 12  # 6 hex bytes -> 12 chars

    def test_default_request_id_is_question_mark(self) -> None:
        clear_log_context()
        assert current_request_id() == "?"


class TestRedactionDenylist:
    def setup_method(self) -> None:
        clear_log_context()

    def teardown_method(self) -> None:
        clear_log_context()

    @pytest.mark.parametrize(
        "key",
        [
            "token",
            "password",
            "session_key",
            "authorization",
            "secret",
            "api_key",
            "bearer",
            "TOKEN",
            "Password",
        ],
    )
    def test_secret_extras_redacted(self, key: str, jsonlog) -> None:
        log = logging.getLogger("test_redact")
        log.info("hello", extra={key: "very-secret-do-not-leak"})
        records = jsonlog()
        assert any(r.get(key) == "(redacted)" for r in records), f"Key {key} should be redacted"
        for r in records:
            assert "very-secret-do-not-leak" not in json.dumps(r)

    def test_non_secret_extras_pass_through(self, jsonlog) -> None:
        log = logging.getLogger("test_redact")
        log.info("hello", extra={"username": "alice", "tool_name": "x"})
        records = jsonlog()
        assert any(r.get("username") == "alice" for r in records)
        assert any(r.get("tool_name") == "x" for r in records)

    def test_redact_keys_not_empty(self) -> None:
        # Defence-in-depth: refactors must not accidentally empty the set.
        assert "token" in _REDACT_KEYS
        assert "password" in _REDACT_KEYS
        assert "session_key" in _REDACT_KEYS


class TestContextFilter:
    def setup_method(self) -> None:
        clear_log_context()

    def teardown_method(self) -> None:
        clear_log_context()

    def test_context_fields_injected(self) -> None:
        update_log_context(request_id="abc", tool_name="splunk_run_query")
        rec = logging.makeLogRecord({"msg": "x"})
        flt = MCPContextFilter()
        assert flt.filter(rec) is True
        assert rec.request_id == "abc"
        assert rec.tool_name == "splunk_run_query"


# ---------------------------------------------------------------------------
# M7 - configure_logging refuses sys.stdout
# ---------------------------------------------------------------------------


class TestConfigureLoggingStdoutGuard:
    """``configure_logging`` must refuse to attach a handler to stdout
    because the MCP stdio transport uses stdout exclusively for
    JSON-RPC frames."""

    def test_refuses_explicit_stdout_stream(self) -> None:
        import sys

        from spl_bridge.logging_config import configure_logging

        with pytest.raises(RuntimeError, match="stdout"):
            configure_logging(stream=sys.stdout)

    def test_accepts_explicit_stderr_stream(self) -> None:
        import sys

        from spl_bridge.logging_config import configure_logging

        configure_logging(stream=sys.stderr)
        root = logging.getLogger()
        assert any(getattr(h, "stream", None) is sys.stderr for h in root.handlers)

    def test_default_stream_is_stderr(self) -> None:
        import sys

        from spl_bridge.logging_config import configure_logging

        configure_logging()
        root = logging.getLogger()
        assert any(getattr(h, "stream", None) is sys.stderr for h in root.handlers)


# ---------------------------------------------------------------------------
# Phase 2 regression: the spl_bridge logger must not propagate, and
# configure_logging() must reset its handlers in lockstep with root so
# every record has exactly one emission path.
# ---------------------------------------------------------------------------


class TestPackageLoggerNoDoubleEmit:
    def test_package_logger_does_not_propagate(self) -> None:
        # Importing the package installs the default handler with
        # propagate=False. Re-import ordering does not matter; the
        # invariant is on the live logger.
        import spl_bridge  # noqa: F401 -- triggers package init

        pkg = logging.getLogger("spl_bridge")
        assert pkg.propagate is False, (
            "spl_bridge logger must be non-propagating; otherwise any "
            "consumer that also configures root will double-emit our "
            "records and corrupt the MCP stdio framing"
        )

    def test_configure_logging_replaces_package_handlers(self) -> None:
        import sys

        from spl_bridge.logging_config import configure_logging

        # Pre-state: package logger has at least one handler.
        pkg = logging.getLogger("spl_bridge")
        assert pkg.handlers, "package init should have installed exactly one handler"

        configure_logging(stream=sys.stderr)

        root = logging.getLogger()
        # Both root and package should now have the SAME handler list,
        # length 1, pointing at stderr. This is the "single emission
        # path" invariant.
        assert len(root.handlers) == 1
        assert len(pkg.handlers) == 1
        assert root.handlers[0] is pkg.handlers[0]
        assert getattr(root.handlers[0], "stream", None) is sys.stderr

    def test_no_duplicate_emission_after_configure(self, capsys) -> None:
        """End-to-end: log one line, see one line on stderr."""
        import sys

        from spl_bridge.logging_config import configure_logging

        configure_logging(stream=sys.stderr)
        log = logging.getLogger("spl_bridge.tests.dup_emit")
        log.info("dup-emit-canary")

        captured = capsys.readouterr()
        # Each emission produces exactly one stderr line. Count the
        # canary token to be specific (caplog noise from other tests
        # could appear; we want to verify the canary is unique).
        n = captured.err.count("dup-emit-canary")
        assert n == 1, f"expected exactly one emission of canary, got {n}: {captured.err!r}"
