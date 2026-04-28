"""Golden SPL safety corpus: allowed / denied / edge cases.

These tests mock the Splunk parser API so they run without a live instance.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from spl_bridge.config import SplunkMCPConfig
from spl_bridge.splunk_client import SplunkClient
from spl_bridge.tool_registry import load_safe_spl


def _make_client() -> SplunkClient:
    cfg = SplunkMCPConfig(host="mock", splunk_token="tok")
    return SplunkClient(cfg)


def _mock_parser_response(commands: list[dict]) -> MagicMock:
    resp = MagicMock()
    resp.status_code = 200
    resp.json.return_value = {"commands": commands}
    return resp


@pytest.fixture()
def safety() -> dict:
    return load_safe_spl()


class TestAllowedQueries:
    """Queries that MUST pass check_spl_safe."""

    @pytest.mark.parametrize(
        "spl,cmds",
        [
            ("search index=main error", [{"command": "search"}]),
            ("| stats count by host", [{"command": "stats"}]),
            ("| tstats count where index=* by index", [{"command": "tstats"}]),
            ("| makeresults count=1 | eval x=1", [{"command": "makeresults"}, {"command": "eval"}]),
            ("| metadata type=hosts index=main", [{"command": "metadata"}]),
            ("| inputlookup my_lookup.csv", [{"command": "inputlookup"}]),
            (
                "search index=main | head 10 | table host source",
                [
                    {"command": "search"},
                    {"command": "head"},
                    {"command": "table"},
                ],
            ),
        ],
    )
    def test_safe_queries_pass(self, spl: str, cmds: list, safety: dict) -> None:
        client = _make_client()
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(client, "call_api", lambda *a, **kw: _mock_parser_response(cmds))
            safe_cmds = set(safety["safe_spl_commands"])
            sub_args = safety["sub_search_arg_cmd"]
            ok, msg = client.check_spl_safe(spl, safe_cmds, sub_args)
            assert ok, f"Expected safe but got: {msg}"


class TestDeniedQueries:
    """Queries that MUST fail check_spl_safe."""

    @pytest.mark.parametrize(
        "spl,cmds",
        [
            ("| rest /services/server/info", [{"command": "rest"}]),
            ("| delete index=main", [{"command": "delete"}]),
            ("| outputlookup bad.csv", [{"command": "outputlookup"}]),
            ("| sendalert my_action", [{"command": "sendalert"}]),
            ("| collect index=summary", [{"command": "collect"}]),
            ("| script python my_script", [{"command": "script"}]),
        ],
    )
    def test_unsafe_queries_blocked(self, spl: str, cmds: list, safety: dict) -> None:
        client = _make_client()
        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(client, "call_api", lambda *a, **kw: _mock_parser_response(cmds))
            safe_cmds = set(safety["safe_spl_commands"])
            sub_args = safety["sub_search_arg_cmd"]
            ok, msg = client.check_spl_safe(spl, safe_cmds, sub_args)
            assert not ok, f"Expected blocked but was allowed for: {spl}"
            assert "Forbidden command" in msg


class TestSubsearchValidation:
    """Subsearch recursion must also be checked."""

    def test_safe_subsearch_passes(self, safety: dict) -> None:
        cmds = [
            {
                "command": "join",
                "rawargs": "[search index=main | fields host]",
            }
        ]
        inner_cmds = [{"command": "search"}, {"command": "fields"}]
        client = _make_client()
        call_count = {"n": 0}

        def mock_call(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _mock_parser_response(cmds)
            return _mock_parser_response(inner_cmds)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(client, "call_api", mock_call)
            ok, msg = client.check_spl_safe(
                "| join [search index=main | fields host]",
                set(safety["safe_spl_commands"]),
                safety["sub_search_arg_cmd"],
            )
            assert ok

    def test_unsafe_subsearch_blocked(self, safety: dict) -> None:
        cmds = [
            {
                "command": "join",
                "rawargs": "[| rest /services/server/info]",
            }
        ]
        inner_cmds = [{"command": "rest"}]
        client = _make_client()
        call_count = {"n": 0}

        def mock_call(*args, **kwargs):
            call_count["n"] += 1
            if call_count["n"] == 1:
                return _mock_parser_response(cmds)
            return _mock_parser_response(inner_cmds)

        with pytest.MonkeyPatch.context() as mp:
            mp.setattr(client, "call_api", mock_call)
            ok, msg = client.check_spl_safe(
                "| join [| rest /services/server/info]",
                set(safety["safe_spl_commands"]),
                safety["sub_search_arg_cmd"],
            )
            assert not ok
            assert "rest" in msg.lower()


class TestRestCommandBlocked:
    """``rest`` is NOT in safe_spl_commands — confirm."""

    def test_rest_not_in_allowlist(self, safety: dict) -> None:
        assert "rest" not in safety["safe_spl_commands"]
