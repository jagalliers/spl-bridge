"""Tests for spl_bridge.splunk_client — NDJSON, normalize, safety checks."""

from __future__ import annotations

import json

import pytest

from spl_bridge.splunk_client import (
    SplunkClient,
    convert_ndjson_to_dict,
    normalize_search_command,
)

GEN_CMDS = {"search", "tstats", "makeresults", "rest", "metadata", "inputlookup"}


class TestConvertNdjson:
    def test_basic_results(self) -> None:
        lines = "\n".join(
            [
                json.dumps({"result": {"host": "web01", "count": "5"}}),
                json.dumps({"result": {"host": "web02", "count": "3"}}),
            ]
        )
        parsed = convert_ndjson_to_dict(lines)
        assert len(parsed.results) == 2
        assert parsed.results[0]["host"] == "web01"
        assert not parsed.errors

    def test_error_messages_collected(self) -> None:
        lines = "\n".join(
            [
                json.dumps({"messages": [{"type": "ERROR", "text": "boom"}]}),
            ]
        )
        parsed = convert_ndjson_to_dict(lines)
        assert parsed.errors == ["boom"]
        assert not parsed.results

    def test_warn_messages_collected(self) -> None:
        lines = json.dumps({"messages": [{"type": "WARN", "text": "slow query"}]})
        parsed = convert_ndjson_to_dict(lines)
        assert "slow query" in parsed.errors

    def test_metadata_stripped(self) -> None:
        line = json.dumps({"result": {"host": "h", "preview": True, "offset": 0}})
        parsed = convert_ndjson_to_dict(line)
        assert "preview" not in parsed.results[0]
        assert "offset" not in parsed.results[0]

    def test_empty_input(self) -> None:
        parsed = convert_ndjson_to_dict("")
        assert not parsed.results
        assert not parsed.errors

    def test_malformed_lines_skipped(self) -> None:
        lines = "not json\n" + json.dumps({"result": {"ok": "1"}})
        parsed = convert_ndjson_to_dict(lines)
        assert len(parsed.results) == 1


class TestNormalizeSearchCommand:
    def test_plain_query_gets_search_prefix(self) -> None:
        result = normalize_search_command("index=main", 1000, GEN_CMDS)
        assert result.startswith("search index=main")
        assert "| head 1001" in result

    def test_pipe_query_no_prefix(self) -> None:
        result = normalize_search_command("| makeresults count=1", 1000, GEN_CMDS)
        assert result.startswith("| makeresults")
        assert "| head 1001" in result

    def test_generating_command_no_prefix(self) -> None:
        result = normalize_search_command("tstats count where index=*", 1000, GEN_CMDS)
        assert result.startswith("tstats")

    def test_search_prefix_already(self) -> None:
        result = normalize_search_command("search index=main error", 500, GEN_CMDS)
        assert result.startswith("search index=main")
        assert "| head 501" in result

    def test_empty_query(self) -> None:
        assert normalize_search_command("", 1000, GEN_CMDS) == ""


class TestSplunkClientBuildAppEndpoint:
    def _client(self) -> SplunkClient:
        from spl_bridge.config import SplunkMCPConfig

        cfg = SplunkMCPConfig(host="h", splunk_token="t")
        return SplunkClient(cfg)

    def test_no_app(self) -> None:
        c = self._client()
        assert c.build_app_endpoint("search/jobs/export") == "services/search/jobs/export"

    def test_with_app(self) -> None:
        c = self._client()
        path = c.build_app_endpoint("search/jobs/export", "search")
        assert path == "servicesNS/-/search/search/jobs/export"

    def test_with_object(self) -> None:
        c = self._client()
        path = c.build_app_endpoint("saved/searches", "-", object_name="MySearch")
        assert path == "servicesNS/-/-/saved/searches/MySearch"

    def test_invalid_app_raises(self) -> None:
        c = self._client()
        with pytest.raises(ValueError, match="Invalid app name"):
            c.build_app_endpoint("x", "../../etc/passwd")


class TestSafeJoinSSRF:
    """M-4: ``call_api`` must reject absolute / protocol-relative URLs in ``path``."""

    def _client(self) -> SplunkClient:
        from spl_bridge.config import SplunkMCPConfig

        cfg = SplunkMCPConfig(host="splunk.example", splunk_token="t")
        return SplunkClient(cfg)

    @pytest.mark.parametrize(
        "evil",
        [
            "https://evil.example/foo",
            "http://evil.example/foo",
            "//evil.example/foo",
            "javascript:alert(1)",
            "file:///etc/passwd",
            "ftp://evil.example/foo",
        ],
    )
    def test_call_api_rejects_absolute_url(self, evil: str) -> None:
        with pytest.raises(ValueError, match="path must be relative"):
            self._client().call_api("GET", evil)

    def test_safe_join_accepts_relative_path(self) -> None:
        from spl_bridge.splunk_client import _safe_join

        url = _safe_join("https://splunk:8089", "services/auth/login")
        assert url == "https://splunk:8089/services/auth/login"

    def test_safe_join_strips_leading_slash(self) -> None:
        from spl_bridge.splunk_client import _safe_join

        url = _safe_join("https://splunk:8089", "/services/x")
        assert url == "https://splunk:8089/services/x"

    def test_safe_join_rejects_non_string(self) -> None:
        from spl_bridge.splunk_client import _safe_join

        with pytest.raises(ValueError, match="must be a string"):
            _safe_join("https://splunk:8089", None)  # type: ignore[arg-type]
