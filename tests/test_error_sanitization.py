"""Verify client-facing errors never leak upstream Splunk response bodies.

Covers G1 leak points:
- ``SplunkClient.export_search`` HTTP non-200
- ``SplunkClient.export_search`` NDJSON-only-errors path
- ``SplunkClient.check_spl_safe`` parser HTTP / JSON failures
- ``SplunkClient.is_saved_search_disabled`` JSON parse failures

Plus R3 regression: top-level exception guard wraps unexpected exceptions.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest
import requests

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.logging_config import clear_log_context, set_request_id
from spl_bridge.splunk_client import SplunkClient

SECRET_BODY = "session_key=abc123-DO-NOT-LEAK; password=hunter2"


def _client() -> SplunkClient:
    cfg = SplunkMCPConfig(host="h", splunk_token="t")
    return SplunkClient(cfg)


def _resp(status: int, text: str = "") -> MagicMock:
    r = MagicMock()
    r.status_code = status
    r.text = text
    if text:
        try:
            r.json.return_value = json.loads(text)
        except Exception:
            r.json.side_effect = json.JSONDecodeError("bad", text, 0)
    return r


@pytest.fixture(autouse=True)
def _rid():
    set_request_id()
    yield
    clear_log_context()


class TestExportSearchSanitization:
    def test_http_error_does_not_leak_body(self) -> None:
        c = _client()
        with patch.object(c, "call_api", return_value=_resp(500, SECRET_BODY)):
            out = c.export_search("search index=main")
        assert "error" in out
        assert "abc123" not in out["error"]
        assert "hunter2" not in out["error"]
        assert "session_key" not in out["error"]
        assert "HTTP 500" in out["error"]
        assert "request_id=" in out["error"]

    def test_ndjson_errors_without_results_generic(self) -> None:
        c = _client()
        ndjson = "\n".join(
            [
                json.dumps({"messages": [{"type": "ERROR", "text": SECRET_BODY}]}),
            ]
        )
        with patch.object(c, "call_api", return_value=_resp(200, ndjson)):
            out = c.export_search("search index=main")
        assert "error" in out
        assert "abc123" not in out["error"]
        assert "hunter2" not in out["error"]
        assert "request_id=" in out["error"]

    def test_connection_error_propagates_for_classifier(self) -> None:
        """``ConnectionError`` must propagate out of export_search so the
        server-level classifier can produce the curated "Could not
        connect to Splunk at host:port" message. Containing the
        secret is the classifier's job (and is covered by the
        ``test_mcp_e2e`` end-to-end suite); here we just lock in the
        propagation contract.
        """
        import requests

        c = _client()
        with (
            patch(
                "spl_bridge.splunk_client.requests.request",
                side_effect=requests.exceptions.ConnectionError(SECRET_BODY),
            ),
            pytest.raises(requests.exceptions.ConnectionError),
        ):
            c.export_search("search index=main")

    def test_generic_request_exception_synthesized_without_leak(self) -> None:
        """Other ``RequestException`` flavours (chunked encoding, decoding,
        etc.) still produce a synthetic 500 with no secret leakage --
        these aren't recoverable transport errors the classifier can
        usefully describe, so the existing curated string applies.
        """
        import requests

        c = _client()
        with patch(
            "spl_bridge.splunk_client.requests.request",
            side_effect=requests.exceptions.ChunkedEncodingError(SECRET_BODY),
        ):
            out = c.export_search("search index=main")
        assert "error" in out
        assert "abc123" not in out["error"]
        assert "hunter2" not in out["error"]
        assert "Splunk API" in out["error"]


class TestCheckSplSafeSanitization:
    def test_parser_http_error_does_not_leak_body(self) -> None:
        c = _client()
        with patch.object(c, "call_api", return_value=_resp(403, SECRET_BODY)):
            ok, msg = c.check_spl_safe("search index=main", {"search"}, {})
        assert ok is False
        assert "abc123" not in msg
        assert "hunter2" not in msg
        assert "HTTP 403" in msg
        assert "request_id=" in msg

    def test_parser_invalid_json_does_not_leak_body(self) -> None:
        c = _client()
        bad = MagicMock()
        bad.status_code = 200
        bad.text = SECRET_BODY
        bad.json.side_effect = json.JSONDecodeError("bad", SECRET_BODY, 0)
        with patch.object(c, "call_api", return_value=bad):
            ok, msg = c.check_spl_safe("search index=main", {"search"}, {})
        assert ok is False
        assert "abc123" not in msg
        assert "hunter2" not in msg
        assert "request_id=" in msg

    # ------------------------------------------------------------------
    # Propagation contract: transport-class exceptions raised from the
    # parser endpoint must escape ``check_spl_safe`` so that
    # ``server._execute_tool``'s classifier produces the curated
    # operationally-useful message ("Could not connect to Splunk at
    # host:port", "Splunk request timed out", "Splunk authentication
    # failed") instead of being misattributed as a safety violation.
    # ------------------------------------------------------------------

    def test_propagates_connection_error(self) -> None:
        c = _client()
        with (
            patch.object(
                c,
                "call_api",
                side_effect=requests.ConnectionError("conn aborted " + SECRET_BODY),
            ),
            pytest.raises(requests.ConnectionError),
        ):
            c.check_spl_safe("search index=main", {"search"}, {})

    def test_propagates_timeout(self) -> None:
        c = _client()
        with (
            patch.object(
                c,
                "call_api",
                side_effect=requests.Timeout("read timeout " + SECRET_BODY),
            ),
            pytest.raises(requests.Timeout),
        ):
            c.check_spl_safe("search index=main", {"search"}, {})

    def test_propagates_splunk_login_error(self) -> None:
        from spl_bridge.auth import SplunkLoginError

        c = _client()
        with (
            patch.object(
                c,
                "call_api",
                side_effect=SplunkLoginError("Splunk login failed (HTTP 401)"),
            ),
            pytest.raises(SplunkLoginError),
        ):
            c.check_spl_safe("search index=main", {"search"}, {})

    def test_logic_error_returns_new_distinguishable_message(self) -> None:
        """Genuinely unexpected logic faults still surface a sanitized
        ``(False, msg)`` tuple, but the message is the renamed
        ``"SPL safety check could not complete"`` -- distinguishable
        from the policy-deny path (``"Forbidden command found: ..."``)
        and from the old misleading ``"SPL validation failed (internal
        error)"`` that previously masked transport faults.
        """
        c = _client()
        with patch.object(c, "call_api", side_effect=TypeError("boom " + SECRET_BODY)):
            ok, msg = c.check_spl_safe("search index=main", {"search"}, {})
        assert ok is False
        assert "SPL safety check could not complete" in msg
        assert "SPL validation failed" not in msg
        assert "abc123" not in msg
        assert "hunter2" not in msg
        assert "request_id=" in msg


class TestSavedSearchSanitization:
    def test_malformed_payload_does_not_leak(self) -> None:
        c = _client()
        bad = MagicMock()
        bad.status_code = 200
        bad.text = SECRET_BODY
        bad.json.return_value = {"unexpected": SECRET_BODY}
        with patch.object(c, "call_api", return_value=bad):
            disabled, msg, app = c.is_saved_search_disabled("foo")
        assert "abc123" not in msg
        assert "hunter2" not in msg
        assert "request_id=" in msg

    def test_invalid_json_does_not_leak(self) -> None:
        c = _client()
        bad = MagicMock()
        bad.status_code = 200
        bad.text = SECRET_BODY
        bad.json.side_effect = json.JSONDecodeError("bad", SECRET_BODY, 0)
        with patch.object(c, "call_api", return_value=bad):
            disabled, msg, app = c.is_saved_search_disabled("foo")
        assert "abc123" not in msg
        assert "hunter2" not in msg
        assert "request_id=" in msg


class TestClassifiedExceptionMessages:
    """Phase 2: server.py classifies known operational exceptions
    (login failure, timeout, connection refused, generic transport)
    into curated, actionable error strings that still don't leak
    upstream content. The fallback ``Internal error`` branch keeps
    its opaque message for genuinely unknown faults.
    """

    @staticmethod
    def _invoke_with_exception(exc: BaseException) -> str:
        """Build a fresh app and trigger the classifier by patching
        ``build_spl`` to raise *exc*. Returns the surfaced error
        message string from the raised ToolExecutionError.
        """
        from spl_bridge.server import ToolExecutionError, _build_mcp_app

        cfg = SplunkMCPConfig(
            host="splunk.example.invalid",
            port=8089,
            splunk_token="t",
        )
        client = MagicMock()
        client.is_saved_search_disabled.return_value = (False, "ok", "search")
        client.check_spl_safe.return_value = (True, "ok")
        client.export_search.return_value = {"results": []}

        app = _build_mcp_app(cfg, client)
        try:
            tool = app._tool_manager._tools["splunk_run_query"]
        except (AttributeError, KeyError):  # pragma: no cover - defensive
            tool = app._tool_manager.list_tools()[0]

        with patch("spl_bridge.server.build_spl", side_effect=exc):
            with pytest.raises(ToolExecutionError) as excinfo:
                tool.fn(query="search index=main")
        return str(excinfo.value)

    def test_splunk_login_error_classified(self) -> None:
        from spl_bridge.auth import SplunkLoginError

        msg = self._invoke_with_exception(
            SplunkLoginError("Splunk login failed (HTTP 401) " + SECRET_BODY)
        )
        assert "Splunk authentication failed" in msg
        assert "request_id=" in msg
        # No upstream body, no host:port leak from the exception
        # message (host:port is allowed in the connection-refused
        # branch only).
        assert "abc123" not in msg
        assert "hunter2" not in msg
        assert "session_key" not in msg

    def test_request_timeout_classified(self) -> None:
        msg = self._invoke_with_exception(
            requests.exceptions.Timeout("read timeout " + SECRET_BODY)
        )
        assert "Splunk request timed out" in msg
        assert "request_id=" in msg
        assert "abc123" not in msg
        assert "hunter2" not in msg

    def test_connection_error_classified_with_host_port(self) -> None:
        msg = self._invoke_with_exception(
            requests.exceptions.ConnectionError("refused " + SECRET_BODY)
        )
        # Operator-supplied config is OK to echo back.
        assert "Could not connect to Splunk" in msg
        assert "splunk.example.invalid" in msg
        assert "8089" in msg
        assert "request_id=" in msg
        assert "abc123" not in msg
        assert "hunter2" not in msg

    def test_generic_request_exception_classified(self) -> None:
        msg = self._invoke_with_exception(
            requests.exceptions.ChunkedEncodingError("boom " + SECRET_BODY)
        )
        assert "transport error" in msg
        assert "splunk.example.invalid" in msg
        assert "request_id=" in msg
        assert "abc123" not in msg
        assert "hunter2" not in msg

    def test_check_spl_safe_connection_error_classified(self) -> None:
        """End-to-end: a ``ConnectionError`` raised from the parser
        endpoint (e.g. Splunk unreachable) flows through
        ``server._execute_tool``'s classifier the same way a
        ``ConnectionError`` from any other Splunk REST call does --
        it must surface as ``"Could not connect to Splunk at host:port"``,
        NOT as ``"Query blocked by safety check: SPL validation failed
        (internal error)"`` (the pre-fix behaviour caused by the
        over-broad ``except Exception:`` in ``check_spl_safe``).
        """
        from spl_bridge.server import ToolExecutionError, _build_mcp_app

        cfg = SplunkMCPConfig(
            host="splunk.example.invalid",
            port=8089,
            splunk_token="t",
        )
        client = MagicMock()
        client.is_saved_search_disabled.return_value = (False, "ok", "search")
        client.check_spl_safe.side_effect = requests.exceptions.ConnectionError(
            "Connection aborted: " + SECRET_BODY
        )

        app = _build_mcp_app(cfg, client)
        try:
            tool = app._tool_manager._tools["splunk_run_query"]
        except (AttributeError, KeyError):  # pragma: no cover - defensive
            tool = app._tool_manager.list_tools()[0]

        with pytest.raises(ToolExecutionError) as excinfo:
            tool.fn(query="search index=main")
        msg = str(excinfo.value)

        assert "Could not connect to Splunk" in msg
        assert "splunk.example.invalid" in msg
        assert "8089" in msg
        assert "request_id=" in msg
        # No leak of upstream body text.
        assert "abc123" not in msg
        assert "hunter2" not in msg
        # And -- the regression we are guarding against -- we must NOT
        # have fallen back into the safety-check misattribution.
        assert "safety check" not in msg.lower()
        assert "SPL validation" not in msg


class TestUnexpectedExceptionGuard:
    """R3 regression: a non-ToolExecutionError must surface as generic msg."""

    def test_unexpected_exception_returns_generic_error(self) -> None:
        from spl_bridge.server import ToolExecutionError, _build_mcp_app

        cfg = SplunkMCPConfig(host="mock", splunk_token="t")
        client = MagicMock()

        _build_mcp_app(cfg, client)

        from spl_bridge.tool_registry import (
            load_builtin_tools,
            mcp_tool_name,
        )

        with patch(
            "spl_bridge.server.build_spl",
            side_effect=RuntimeError("internal traceback secret-token=xyz123"),
        ):
            from spl_bridge.server import _build_mcp_app as build

            mcp = build(cfg, client)

            tool_fn = None
            tools = load_builtin_tools()
            for t in tools:
                if mcp_tool_name(t) == "splunk_run_query":
                    tool_fn = t
                    break
            assert tool_fn is not None

            client.is_saved_search_disabled.return_value = (False, "ok", "search")
            client.check_spl_safe.return_value = (True, "ok")
            client.export_search.return_value = {"results": []}

            from mcp.server.fastmcp import FastMCP

            assert isinstance(mcp, FastMCP)

            # Use the internal _execute_tool by reproducing what the
            # registered handler would do: simulate the same path that
            # raises and verify the wrapper.

            # Reach _execute_tool via tool registration: the closure was
            # wired during _build_mcp_app. We rebuild a fresh app and
            # invoke through patched build_spl to trigger the guard.
            patched_app = build(cfg, client)
            # Find the registered FastMCP tool function.
            try:
                tool = patched_app._tool_manager._tools["splunk_run_query"]
            except (AttributeError, KeyError):
                tool = patched_app._tool_manager.list_tools()[0]
            # Call the underlying fn with secret-leaking RuntimeError patched in.
            with (
                patch(
                    "spl_bridge.server.build_spl",
                    side_effect=RuntimeError("internal traceback secret-token=xyz123"),
                ),
                pytest.raises(ToolExecutionError) as excinfo,
            ):
                tool.fn(query="search index=main")
            err = str(excinfo.value)
            assert "xyz123" not in err
            assert "Internal error" in err
            assert "request_id=" in err
