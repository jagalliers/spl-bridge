"""Coverage for the remaining P2 fixes:
R7  - NDJSON warnings beside results (no raw text leak)
R10 - tool registration assertion
R12 - SplunkClient uses requests.Session for connection pooling
R13 - configure_logging shared by server and doctor
R14 - cli.py defaults to ``serve`` when no subcommand is given
"""

from __future__ import annotations

import logging
from unittest.mock import MagicMock, patch

import pytest

from spl_bridge.cli import main as cli_main
from spl_bridge.config import SplunkMCPConfig
from spl_bridge.logging_config import (
    MCPContextFilter,
    MCPJsonFormatter,
    configure_logging,
)
from spl_bridge.server import _register_tool
from spl_bridge.splunk_client import SplunkClient

# ---------------------------------------------------------------------------
# R7 - NDJSON warnings alongside results
# ---------------------------------------------------------------------------


def _ndjson_lines(*lines: str) -> str:
    return "\n".join(lines) + "\n"


class TestNdjsonWarningsBesideResults:
    def test_results_with_errors_returns_results_plus_warning(self) -> None:
        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        client = SplunkClient(cfg)

        ndjson = _ndjson_lines(
            '{"result": {"_time": "1", "host": "h1"}}',
            '{"messages": [{"type": "ERROR", "text": "internal stack trace 0xDEADBEEF"}]}',
            '{"result": {"_time": "2", "host": "h2"}}',
        )
        fake_resp = MagicMock(status_code=200, text=ndjson)
        with patch.object(client, "call_api", return_value=fake_resp):
            out = client.export_search("search index=main", row_limit=10)

        assert "results" in out
        assert len(out["results"]) == 2
        assert "warnings" in out
        # The raw upstream text must not leak into the client-facing output.
        assert "0xDEADBEEF" not in str(out)
        assert "stack trace" not in str(out)
        assert any("error message" in w for w in out["warnings"])

    def test_results_only_no_warnings_field(self) -> None:
        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        client = SplunkClient(cfg)
        ndjson = _ndjson_lines('{"result": {"a": 1}}')
        fake_resp = MagicMock(status_code=200, text=ndjson)
        with patch.object(client, "call_api", return_value=fake_resp):
            out = client.export_search("search index=main", row_limit=10)
        assert "warnings" not in out


# ---------------------------------------------------------------------------
# R10 - tool registration safety net
# ---------------------------------------------------------------------------


class TestToolRegistrationAssert:
    def test_unknown_param_shape_raises_runtime_error(self) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        # Schema with an unknown parameter set that no _register_tool branch
        # handles.
        schema_props = {"completely_made_up_param": {"type": "string"}}
        with pytest.raises(RuntimeError, match="does not match any known"):
            _register_tool(
                mcp,
                "splunk_made_up_tool",
                "test",
                schema_props,
                lambda *_: {},
            )

    def test_known_param_shape_registers_cleanly(self) -> None:
        from mcp.server.fastmcp import FastMCP

        mcp = FastMCP("test")
        schema_props = {"query": {"type": "string"}}
        _register_tool(
            mcp,
            "splunk_query_tool",
            "test",
            schema_props,
            lambda *_: {"results": []},
        )


# ---------------------------------------------------------------------------
# Transport - per-call ``requests.request`` (no pooled Session)
#
# R12 originally reused a single ``requests.Session`` to pool TCP/TLS
# across calls. That exposed a ``urllib3`` keep-alive race on Splunk
# Cloud / load-balanced endpoints (``RemoteDisconnected`` / ``Connection
# aborted``). The transport now mirrors Splunk's own reference MCP
# server (``Splunk_MCP_Server/bin/splunk_api.py``) and issues each REST
# call via ``requests.request(...)``; the contract these tests pin is
# that we no longer hold a ``_session`` attribute and each ``call_api``
# invocation produces one outbound ``requests.request`` call.
# ---------------------------------------------------------------------------


class TestSplunkClientTransport:
    def test_uses_no_session_pooling(self) -> None:
        """Each ``call_api`` invocation issues its own ``requests.request(...)``
        - we no longer pool a ``Session``, mirroring Splunk_MCP_Server.
        """
        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        client = SplunkClient(cfg)
        assert not hasattr(client, "_session")

        with patch("spl_bridge.splunk_client.requests.request") as mock_req:
            mock_req.return_value = MagicMock(status_code=200, text="{}")
            client.call_api("GET", "services/data/indexes")
            client.call_api("GET", "services/data/indexes")
            assert mock_req.call_count == 2

    def test_close_is_idempotent(self) -> None:
        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        client = SplunkClient(cfg)
        # ``close()`` is preserved as an API back-compat no-op now that
        # there is no ``Session`` to release. Calling it twice must not
        # raise.
        client.close()
        client.close()


# ---------------------------------------------------------------------------
# R13 - shared configure_logging
# ---------------------------------------------------------------------------


class TestConfigureLogging:
    def test_installs_json_formatter_and_filter(self) -> None:
        configure_logging()
        root = logging.getLogger()
        assert len(root.handlers) == 1
        h = root.handlers[0]
        assert isinstance(h.formatter, MCPJsonFormatter)
        assert any(isinstance(f, MCPContextFilter) for f in h.filters)

    def test_idempotent_replace(self) -> None:
        configure_logging()
        configure_logging()
        assert len(logging.getLogger().handlers) == 1

    def test_doctor_uses_configure_logging(self, monkeypatch) -> None:
        from spl_bridge import doctor

        called = {}

        def fake_configure(*a, **kw):
            called["yes"] = True

        monkeypatch.setattr(doctor, "configure_logging", fake_configure)
        monkeypatch.setattr(
            doctor,
            "SplunkMCPConfig",
            MagicMock(from_env=MagicMock(side_effect=RuntimeError("stop early"))),
        )
        with pytest.raises(SystemExit):
            doctor.run_doctor()
        assert called.get("yes") is True


# ---------------------------------------------------------------------------
# R14 - cli defaults to ``serve``
# ---------------------------------------------------------------------------


class TestCliDefault:
    def test_no_args_invokes_serve(self, monkeypatch) -> None:
        monkeypatch.setattr("sys.argv", ["spl-bridge"])
        called = {}

        def fake_serve():
            called["serve"] = True

        with patch("spl_bridge.server.main", fake_serve):
            cli_main()

        assert called.get("serve") is True

    def test_explicit_doctor_routes_to_doctor(self, monkeypatch) -> None:
        monkeypatch.setattr("sys.argv", ["spl-bridge", "doctor"])
        called = {}

        def fake_doctor():
            called["doctor"] = True

        with patch("spl_bridge.doctor.run_doctor", fake_doctor):
            cli_main()

        assert called.get("doctor") is True
