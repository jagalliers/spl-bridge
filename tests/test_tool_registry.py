"""Tests for spl_bridge.tool_registry."""

from __future__ import annotations

import pytest

from spl_bridge.tool_registry import (
    build_spl,
    load_builtin_tools,
    load_generating_commands,
    load_safe_spl,
    mcp_tool_name,
)


class TestLoadResources:
    def test_builtin_tools_count(self) -> None:
        tools = load_builtin_tools()
        assert len(tools) == 10

    def test_no_ai_tools(self) -> None:
        tools = load_builtin_tools()
        names = {t["name"] for t in tools}
        assert "generate_spl" not in names
        assert "explain_spl" not in names
        assert "ask_splunk_question" not in names
        assert "optimize_spl" not in names

    def test_safe_spl_commands(self) -> None:
        data = load_safe_spl()
        cmds = data["safe_spl_commands"]
        assert "search" in cmds
        assert "rest" not in cmds

    def test_exclude_tools_no_saia(self) -> None:
        data = load_safe_spl()
        excludes = data["exclude_tools"]
        assert not any(e.startswith("saia_") for e in excludes)
        assert "splunk_get_info" in excludes

    def test_generating_commands(self) -> None:
        gen = load_generating_commands()
        assert "search" in gen
        assert "rest" in gen
        assert "makeresults" in gen


class TestMcpToolName:
    def test_standard_prefix(self) -> None:
        tool = {"name": "run_query", "_meta": {"external_app_id": "splunk"}}
        assert mcp_tool_name(tool) == "splunk_run_query"

    def test_custom_prefix(self) -> None:
        tool = {"name": "foo", "_meta": {"name_prefix": "custom"}}
        assert mcp_tool_name(tool) == "custom_foo"


class TestBuildSpl:
    def _tool(
        self,
        template: str,
        props: dict | None = None,
        row_limiter: bool = False,
        time_range: bool = False,
    ) -> dict:
        return {
            "name": "test",
            "inputSchema": {
                "type": "object",
                "properties": props or {},
            },
            "_meta": {
                "external_app_id": "splunk",
                "execution": {
                    "type": "spl",
                    "template": template,
                    "row_limiter": row_limiter,
                    "time_range": time_range,
                },
            },
        }

    def test_simple_template(self) -> None:
        tool = self._tool("| rest /services/server/info")
        spl, limit, earliest, latest = build_spl(
            tool, {}, default_row_limit=100, max_row_limit=1000
        )
        assert spl == "| rest /services/server/info"
        assert limit is None

    def test_arg_substitution(self) -> None:
        tool = self._tool(
            "| rest /services/data/indexes | search title=$index_name$",
            props={
                "index_name": {"type": "string", "_meta": {"formatting": {"needs_quoting": True}}}
            },
        )
        spl, *_ = build_spl(tool, {"index_name": "main"}, default_row_limit=100, max_row_limit=1000)
        assert '"main"' in spl

    def test_row_limit(self) -> None:
        tool = self._tool("$query$", props={"query": {"type": "string"}}, row_limiter=True)
        _, limit, _, _ = build_spl(
            tool, {"query": "search *"}, default_row_limit=100, max_row_limit=1000
        )
        assert limit == 100

    def test_row_limit_capped(self) -> None:
        tool = self._tool("$query$", props={"query": {"type": "string"}}, row_limiter=True)
        _, limit, _, _ = build_spl(
            tool, {"query": "x", "row_limit": 5000}, default_row_limit=100, max_row_limit=1000
        )
        assert limit == 1000

    def test_time_range(self) -> None:
        tool = self._tool("$query$", props={"query": {"type": "string"}}, time_range=True)
        _, _, earliest, latest = build_spl(
            tool,
            {"query": "x", "earliest_time": "-1h", "latest_time": "now"},
            default_row_limit=100,
            max_row_limit=1000,
        )
        assert earliest == "-1h"
        assert latest == "now"

    def test_type_spl_map_valid(self) -> None:
        tool = {
            "name": "knowledge",
            "inputSchema": {
                "type": "object",
                "properties": {"type": {"type": "string", "enum": ["macros"]}},
            },
            "_meta": {
                "external_app_id": "splunk",
                "_type_spl_map": {
                    "macros": "| rest /services/data/macros count=0",
                },
                "execution": {
                    "type": "spl",
                    "template": "$type$",
                    "row_limiter": True,
                    "time_range": False,
                },
            },
        }
        spl, *_ = build_spl(tool, {"type": "macros"}, default_row_limit=100, max_row_limit=1000)
        assert spl == "| rest /services/data/macros count=0"

    def test_quoting_escapes_embedded_double_quotes(self) -> None:
        tool = self._tool(
            "| savedsearch $name$",
            props={"name": {"type": "string", "_meta": {"formatting": {"needs_quoting": True}}}},
        )
        spl, *_ = build_spl(
            tool,
            {"name": 'My "Custom" Search'},
            default_row_limit=100,
            max_row_limit=1000,
        )
        assert r"My \"Custom\" Search" in spl
        assert spl.count('"') >= 4

    def test_quoting_escapes_backslashes(self) -> None:
        tool = self._tool(
            "| savedsearch $name$",
            props={"name": {"type": "string", "_meta": {"formatting": {"needs_quoting": True}}}},
        )
        spl, *_ = build_spl(
            tool,
            {"name": r"path\to\thing"},
            default_row_limit=100,
            max_row_limit=1000,
        )
        assert r"path\\to\\thing" in spl

    def test_quoting_neutralises_spl_metacharacters(self) -> None:
        tool = self._tool(
            "| savedsearch $name$",
            props={"name": {"type": "string", "_meta": {"formatting": {"needs_quoting": True}}}},
        )
        spl, *_ = build_spl(
            tool,
            {"name": '"; | delete'},
            default_row_limit=100,
            max_row_limit=1000,
        )
        assert "| delete" not in spl.replace(r"\"", "").split('"', 2)[-1]

    def test_type_spl_map_invalid_key_rejected(self) -> None:
        tool = {
            "name": "knowledge",
            "inputSchema": {
                "type": "object",
                "properties": {"type": {"type": "string"}},
            },
            "_meta": {
                "external_app_id": "splunk",
                "_type_spl_map": {"macros": "| rest /services/data/macros"},
                "execution": {
                    "type": "spl",
                    "template": "$type$",
                    "row_limiter": False,
                    "time_range": False,
                },
            },
        }
        with pytest.raises(ValueError, match="Unknown type"):
            build_spl(
                tool, {"type": "| rest /etc/passwd"}, default_row_limit=100, max_row_limit=1000
            )
