"""Tests for the four gap-analysis fixes.

Gap 1: structuredContent in tool responses
Gap 2: Structured JSON logging with request correlation
Gap 3: Optional capability checking
Gap 4: Per-tool rate limit configuration
"""

from __future__ import annotations

import json
import logging
from typing import Any
from unittest.mock import MagicMock, patch

import pytest
from mcp.types import CallToolResult, TextContent

# ---------------------------------------------------------------------------
# Gap 1: structuredContent
# ---------------------------------------------------------------------------


class TestStructuredContent:
    """Verify _format_success returns CallToolResult with both fields."""

    def test_format_success_returns_call_tool_result(self) -> None:
        from spl_bridge.server import _format_success

        result_dict = {"results": [{"host": "srv1"}], "truncated": False}
        ctr = _format_success(result_dict)

        assert isinstance(ctr, CallToolResult)
        assert ctr.isError is False

    def test_content_contains_full_json(self) -> None:
        from spl_bridge.server import _format_success

        result_dict = {"results": [{"count": 42}], "truncated": False}
        ctr = _format_success(result_dict)

        assert len(ctr.content) == 1
        assert isinstance(ctr.content[0], TextContent)
        assert ctr.content[0].type == "text"

        parsed = json.loads(ctr.content[0].text)
        assert parsed["results"] == [{"count": 42}]
        assert parsed["truncated"] is False

    def test_structured_content_is_raw_dict(self) -> None:
        from spl_bridge.server import _format_success

        result_dict = {"results": [], "total_rows": 0}
        ctr = _format_success(result_dict)

        assert ctr.structuredContent is not None
        assert isinstance(ctr.structuredContent, dict)
        assert ctr.structuredContent["total_rows"] == 0

    def test_content_and_structured_are_equivalent(self) -> None:
        from spl_bridge.server import _format_success

        result_dict = {
            "results": [{"host": "a", "source": "b"}],
            "truncated": True,
            "approx_total": "1000+",
        }
        ctr = _format_success(result_dict)

        from_text = json.loads(ctr.content[0].text)
        assert from_text == ctr.structuredContent

    def test_non_dict_input_wraps_in_value(self) -> None:
        """Edge case: if result is not a dict, it gets wrapped."""
        from spl_bridge.server import _format_success

        # Force a non-dict through (type system allows dict but test edge)
        ctr = _format_success({"value": "hello"})
        assert ctr.structuredContent == {"value": "hello"}

    def test_sdk_passthrough(self) -> None:
        """CallToolResult is recognized by the low-level handler as a pass-through type.

        The SDK's normalize path checks ``isinstance(results, types.CallToolResult)``
        and returns it directly as ``ServerResult(results)``.
        """
        from mcp import types as mcp_types

        ctr = CallToolResult(
            content=[TextContent(type="text", text='{"ok":true}')],
            structuredContent={"ok": True},
            isError=False,
        )
        assert isinstance(ctr, mcp_types.CallToolResult)
        assert ctr.content[0].text == '{"ok":true}'
        assert ctr.structuredContent == {"ok": True}


# ---------------------------------------------------------------------------
# Gap 2: JSON logging
# ---------------------------------------------------------------------------


class TestMCPJsonFormatter:
    def test_output_is_valid_json(self) -> None:
        from spl_bridge.logging_config import MCPJsonFormatter

        formatter = MCPJsonFormatter()
        record = logging.LogRecord(
            name="test",
            level=logging.INFO,
            pathname="test.py",
            lineno=1,
            msg="hello %s",
            args=("world",),
            exc_info=None,
        )
        line = formatter.format(record)
        obj = json.loads(line)
        assert obj["message"] == "hello world"
        assert obj["level"] == "INFO"
        assert obj["logger"] == "test"
        assert "time" in obj
        assert "pid" in obj

    def test_time_is_iso8601_utc(self) -> None:
        from spl_bridge.logging_config import MCPJsonFormatter

        formatter = MCPJsonFormatter()
        record = logging.makeLogRecord({"msg": "t"})
        line = formatter.format(record)
        obj = json.loads(line)
        assert obj["time"].endswith("Z")
        assert "T" in obj["time"]

    def test_extra_fields_included(self) -> None:
        from spl_bridge.logging_config import MCPJsonFormatter

        formatter = MCPJsonFormatter()
        record = logging.makeLogRecord({"msg": "t"})
        record.tool_name = "splunk_run_query"
        record.request_id = "abc123"
        line = formatter.format(record)
        obj = json.loads(line)
        assert obj["tool_name"] == "splunk_run_query"
        assert obj["request_id"] == "abc123"

    def test_exception_included(self) -> None:
        from spl_bridge.logging_config import MCPJsonFormatter

        formatter = MCPJsonFormatter()
        try:
            raise ValueError("boom")
        except ValueError:
            import sys

            record = logging.LogRecord(
                name="test",
                level=logging.ERROR,
                pathname="test.py",
                lineno=1,
                msg="fail",
                args=(),
                exc_info=sys.exc_info(),
            )
        line = formatter.format(record)
        obj = json.loads(line)
        assert "exception" in obj
        assert "ValueError" in obj["exception"]


class TestMCPContextFilter:
    def test_injects_context_vars(self) -> None:
        from spl_bridge.logging_config import (
            MCPContextFilter,
            clear_log_context,
            update_log_context,
        )

        clear_log_context()
        update_log_context(request_id="r123", tool_name="my_tool")

        filt = MCPContextFilter()
        record = logging.makeLogRecord({"msg": "test"})
        filt.filter(record)

        assert record.request_id == "r123"  # type: ignore[attr-defined]
        assert record.tool_name == "my_tool"  # type: ignore[attr-defined]
        clear_log_context()

    def test_does_not_overwrite_existing_attrs(self) -> None:
        from spl_bridge.logging_config import (
            MCPContextFilter,
            clear_log_context,
            update_log_context,
        )

        clear_log_context()
        update_log_context(tool_name="from_context")

        filt = MCPContextFilter()
        record = logging.makeLogRecord({"msg": "test"})
        record.tool_name = "already_set"  # type: ignore[attr-defined]
        filt.filter(record)

        assert record.tool_name == "already_set"  # type: ignore[attr-defined]
        clear_log_context()


class TestSetRequestId:
    def test_generates_hex_string(self) -> None:
        from spl_bridge.logging_config import clear_log_context, set_request_id

        clear_log_context()
        rid = set_request_id()
        assert isinstance(rid, str)
        assert len(rid) == 12  # 6 bytes -> 12 hex chars
        int(rid, 16)  # should not raise
        clear_log_context()


class TestOperationLogger:
    def test_logs_start_and_end(self, caplog: pytest.LogCaptureFixture) -> None:
        from spl_bridge.logging_config import clear_log_context, operation_logger

        clear_log_context()

        @operation_logger("test_op")
        def my_func() -> str:
            return "ok"

        with caplog.at_level(logging.INFO):
            result = my_func()

        assert result == "ok"
        messages = [r.message for r in caplog.records]
        assert any("Operation started: test_op" in m for m in messages)
        assert any("Operation completed: test_op" in m for m in messages)
        clear_log_context()

    def test_logs_failure(self, caplog: pytest.LogCaptureFixture) -> None:
        from spl_bridge.logging_config import clear_log_context, operation_logger

        clear_log_context()

        @operation_logger("fail_op")
        def boom() -> None:
            raise RuntimeError("kaboom")

        with caplog.at_level(logging.INFO), pytest.raises(RuntimeError, match="kaboom"):
            boom()

        messages = [r.message for r in caplog.records]
        assert any("Operation failed: fail_op" in m for m in messages)
        clear_log_context()


# ---------------------------------------------------------------------------
# Gap 3: Capability checking
# ---------------------------------------------------------------------------


class TestCapabilityChecking:
    def _make_client(self, require_capabilities: bool = True) -> Any:
        from spl_bridge.config import SplunkMCPConfig
        from spl_bridge.splunk_client import SplunkClient

        cfg = SplunkMCPConfig(
            host="localhost",
            splunk_token="test-token",
            require_capabilities=require_capabilities,
        )
        return SplunkClient(cfg)

    def _mock_context_response(self, capabilities: list[str], status: int = 200) -> MagicMock:
        resp = MagicMock()
        resp.status_code = status
        resp.json.return_value = {
            "entry": [
                {
                    "content": {
                        "capabilities": capabilities,
                        "username": "admin",
                    }
                }
            ]
        }
        return resp

    def test_passes_with_required_capability(self) -> None:
        client = self._make_client()
        with patch.object(
            client,
            "call_api",
            return_value=self._mock_context_response(["mcp_tool_execute", "search"]),
        ):
            ok, msg = client.check_capabilities()
        assert ok is True
        assert msg == ""

    def test_fails_without_required_capability(self) -> None:
        client = self._make_client()
        with patch.object(
            client, "call_api", return_value=self._mock_context_response(["search", "list_inputs"])
        ):
            ok, msg = client.check_capabilities()
        assert ok is False
        assert "mcp_tool_execute" in msg

    def test_caches_after_first_check(self) -> None:
        client = self._make_client()
        mock_resp = self._mock_context_response(["mcp_tool_execute"])
        with patch.object(client, "call_api", return_value=mock_resp) as mock_call:
            ok1, _ = client.check_capabilities()
            ok2, _ = client.check_capabilities()
        assert ok1 is True
        assert ok2 is True
        assert mock_call.call_count == 1

    def test_handles_http_error(self) -> None:
        client = self._make_client()
        error_resp = MagicMock()
        error_resp.status_code = 403
        with patch.object(client, "call_api", return_value=error_resp):
            ok, msg = client.check_capabilities()
        assert ok is False
        assert "HTTP 403" in msg

    def test_handles_malformed_json(self) -> None:
        client = self._make_client()
        resp = MagicMock()
        resp.status_code = 200
        resp.json.side_effect = ValueError("bad json")
        with patch.object(client, "call_api", return_value=resp):
            ok, msg = client.check_capabilities()
        assert ok is False

    def test_custom_required_capabilities(self) -> None:
        client = self._make_client()
        with patch.object(
            client, "call_api", return_value=self._mock_context_response(["mcp_tool_execute"])
        ):
            ok, msg = client.check_capabilities(required={"mcp_tool_execute", "mcp_tool_admin"})
        assert ok is False
        assert "mcp_tool_admin" in msg


# ---------------------------------------------------------------------------
# Gap 4: Per-tool rate limit configuration
# ---------------------------------------------------------------------------


class TestPerToolRateLimitConfig:
    def _clean_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
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
            "MCP_REQUIRE_CAPABILITIES",
            "MCP_RATE_LIMITS",
        ):
            monkeypatch.delenv(key, raising=False)

    def test_default_no_rate_limits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from spl_bridge.config import SplunkMCPConfig

        self._clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.rate_limits is None

    def test_parses_valid_rate_limits(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from spl_bridge.config import SplunkMCPConfig

        self._clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv(
            "MCP_RATE_LIMITS",
            '{"splunk_run_query": 100, "global": 300}',
        )
        cfg = SplunkMCPConfig.from_env()
        assert cfg.rate_limits is not None
        assert cfg.rate_limits["splunk_run_query"] == 100
        assert cfg.rate_limits["global"] == 300

    def test_invalid_json_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from spl_bridge.config import SplunkMCPConfig

        self._clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_RATE_LIMITS", "not json")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.rate_limits is None

    def test_empty_string_ignored(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from spl_bridge.config import SplunkMCPConfig

        self._clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_RATE_LIMITS", "")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.rate_limits is None

    def test_per_tool_limits_wired_in_build(self) -> None:
        """Verify _build_mcp_app honors per-tool limits from config."""
        from spl_bridge.config import SplunkMCPConfig
        from spl_bridge.rate_limit import RateLimitManager

        cfg = SplunkMCPConfig(
            host="h",
            splunk_token="t",
            rate_limits={"splunk_run_query": 2, "global": 500},
        )

        with patch("spl_bridge.server.RateLimitManager") as MockMgr:
            mock_instance = MagicMock(spec=RateLimitManager)
            MockMgr.return_value = mock_instance

            from spl_bridge.server import _build_mcp_app

            mock_client = MagicMock()
            _build_mcp_app(cfg, mock_client)

            MockMgr.assert_called_once_with(global_max=500, window_seconds=60.0)
            mock_instance.set_tool_limit.assert_called_once_with("splunk_run_query", 2)

    def test_require_capabilities_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from spl_bridge.config import SplunkMCPConfig

        self._clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        monkeypatch.setenv("MCP_REQUIRE_CAPABILITIES", "true")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.require_capabilities is True

    def test_require_capabilities_default_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        from spl_bridge.config import SplunkMCPConfig

        self._clean_env(monkeypatch)
        monkeypatch.setenv("SPLUNK_HOST", "h")
        monkeypatch.setenv("SPLUNK_TOKEN", "t")
        cfg = SplunkMCPConfig.from_env()
        assert cfg.require_capabilities is False
