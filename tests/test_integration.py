"""Integration tests against a live Splunk instance.

Gate: set SPLUNK_INTEGRATION=1 in the environment to run these tests.
Also requires SPLUNK_HOST, SPLUNK_PORT, and auth env vars (token or user/pass).

Two layers:
  A. SplunkClient direct -- exercises HTTP/REST without MCP overhead.
  B. Full MCP round-trip  -- starts the server as a subprocess and talks
     MCP JSON-RPC via the SDK ClientSession over stdio.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import asynccontextmanager

import pytest

pytestmark = pytest.mark.skipif(
    os.environ.get("SPLUNK_INTEGRATION") != "1",
    reason="Set SPLUNK_INTEGRATION=1 to run live Splunk tests",
)


# Forwarded credential vars + behavioral knobs only. We deliberately do NOT
# inherit the parent shell's full environment so unrelated secrets
# (AWS_*, ANTHROPIC_*, GITHUB_TOKEN, etc.) cannot leak into the subprocess.
_FORWARDED_VARS = (
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
)


def _minimal_subprocess_env() -> dict[str, str]:
    env: dict[str, str] = {"PATH": os.environ.get("PATH", "")}
    for var in _FORWARDED_VARS:
        if var in os.environ:
            env[var] = os.environ[var]
    env.setdefault("SPLUNK_HOST", "localhost")
    env.setdefault("SPLUNK_PORT", "8089")
    env.setdefault("SPLUNK_VERIFY_SSL", "false")
    return env


@pytest.fixture(scope="module")
def splunk_config():
    from spl_bridge.auth import reset_session
    from spl_bridge.config import SplunkMCPConfig

    reset_session()
    return SplunkMCPConfig.from_env()


@pytest.fixture(scope="module")
def splunk_client(splunk_config):
    from spl_bridge.splunk_client import SplunkClient

    return SplunkClient(splunk_config)


@pytest.fixture(scope="module")
def safe_spl_data():
    from spl_bridge.tool_registry import load_safe_spl

    return load_safe_spl()


@pytest.fixture(scope="module")
def generating_commands():
    from spl_bridge.tool_registry import load_generating_commands

    return load_generating_commands()


# ---------------------------------------------------------------------------
# Layer A: SplunkClient direct
# ---------------------------------------------------------------------------


class TestClientAuth:
    def test_current_context_returns_200(self, splunk_client):
        resp = splunk_client.call_api(
            "GET",
            "services/authentication/current-context",
            params={"output_mode": "json"},
        )
        assert resp.status_code == 200
        body = resp.json()
        username = body["entry"][0]["content"]["username"]
        assert username, "Expected a non-empty username"


class TestClientExport:
    def test_makeresults_returns_one_row(self, splunk_client):
        result = splunk_client.export_search("| makeresults count=1")
        assert "error" not in result
        assert len(result["results"]) == 1

    def test_row_limit_caps_results(self, splunk_client):
        result = splunk_client.export_search("| makeresults count=10", row_limit=3)
        assert "error" not in result
        assert len(result["results"]) == 3
        assert result["truncated"] is True

    def test_time_range_accepted(self, splunk_client):
        result = splunk_client.export_search(
            "| makeresults count=1",
            earliest_time="-1h",
            latest_time="now",
        )
        assert "error" not in result
        assert len(result["results"]) >= 1


class TestClientParser:
    def test_parser_returns_commands_structure(self, splunk_client, safe_spl_data):
        """Validate the real parser response has the structure our code expects."""
        safe_commands = set(safe_spl_data.get("safe_spl_commands", []))
        sub_search_arg_cmd = safe_spl_data.get("sub_search_arg_cmd", {})

        is_safe, msg = splunk_client.check_spl_safe(
            "search index=_internal | head 1",
            safe_commands,
            sub_search_arg_cmd,
        )
        assert is_safe is True, f"Expected safe query to pass: {msg}"

    def test_unsafe_command_blocked(self, splunk_client, safe_spl_data):
        safe_commands = set(safe_spl_data.get("safe_spl_commands", []))
        sub_search_arg_cmd = safe_spl_data.get("sub_search_arg_cmd", {})

        is_safe, msg = splunk_client.check_spl_safe("| delete", safe_commands, sub_search_arg_cmd)
        assert is_safe is False
        assert "delete" in msg.lower()

    def test_rest_excluded_from_safe_commands(self, safe_spl_data):
        """``rest`` is not in safe_spl_commands because tools using it are
        in ``exclude_tools`` and skip the safety check entirely."""
        safe_commands = set(safe_spl_data.get("safe_spl_commands", []))
        assert "rest" not in safe_commands

    def test_exclude_tools_lists_rest_based_tools(self, safe_spl_data):
        exclude = set(safe_spl_data.get("exclude_tools", []))
        assert "splunk_get_info" in exclude
        assert "splunk_get_indexes" in exclude


class TestClientSavedSearch:
    def test_nonexistent_saved_search(self, splunk_client):
        disabled, msg, app = splunk_client.is_saved_search_disabled(
            "nonexistent_search_abc_xyz_99999"
        )
        assert disabled is False
        assert "not found" in msg.lower()


# ---------------------------------------------------------------------------
# Layer B: Full MCP round-trip via SDK
# ---------------------------------------------------------------------------


@asynccontextmanager
async def _mcp_session():
    """Start the server subprocess and return a connected ClientSession."""
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    env = _minimal_subprocess_env()

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "spl_bridge", "serve"],
        env=env,
        cwd=os.path.dirname(os.path.dirname(__file__)),
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


@pytest.fixture(scope="module")
def expected_tool_names():
    from spl_bridge.tool_registry import load_builtin_tools, mcp_tool_name

    return {mcp_tool_name(t) for t in load_builtin_tools()}


@pytest.mark.asyncio
async def test_mcp_initialize():
    async with _mcp_session() as session:
        assert session is not None


@pytest.mark.asyncio
async def test_mcp_list_tools(expected_tool_names):
    async with _mcp_session() as session:
        result = await session.list_tools()
        names = {t.name for t in result.tools}
        assert expected_tool_names <= names, f"Missing tools: {expected_tool_names - names}"
        assert len(result.tools) == len(expected_tool_names)


@pytest.mark.asyncio
async def test_mcp_get_splunk_info():
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_get_info", {})
        assert result.isError is False
        assert len(result.content) > 0
        data = json.loads(result.content[0].text)
        assert "results" in data


@pytest.mark.asyncio
async def test_mcp_run_query_makeresults():
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_run_query", {"query": "| makeresults count=1"})
        assert result.isError is False
        data = json.loads(result.content[0].text)
        assert len(data["results"]) == 1


@pytest.mark.asyncio
async def test_mcp_get_knowledge_objects_lookups():
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_get_knowledge_objects", {"type": "lookups"})
        assert result.isError is False
        data = json.loads(result.content[0].text)
        assert "results" in data


@pytest.mark.asyncio
async def test_mcp_get_knowledge_objects_apps():
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_get_knowledge_objects", {"type": "apps"})
        assert result.isError is False
        data = json.loads(result.content[0].text)
        assert len(data["results"]) > 0


@pytest.mark.asyncio
async def test_mcp_get_metadata_sourcetypes():
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_get_metadata", {"type": "sourcetypes"})
        assert result.isError is False
        data = json.loads(result.content[0].text)
        assert "results" in data


@pytest.mark.asyncio
async def test_mcp_get_indexes():
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_get_indexes", {})
        assert result.isError is False
        data = json.loads(result.content[0].text)
        assert len(data["results"]) > 0


@pytest.mark.asyncio
async def test_mcp_get_index_info():
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_get_index_info", {"index_name": "_internal"})
        assert result.isError is False
        data = json.loads(result.content[0].text)
        assert len(data["results"]) >= 1


@pytest.mark.asyncio
async def test_mcp_unsafe_query_returns_error():
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_run_query", {"query": "| delete"})
        assert result.isError is True
        text = " ".join(c.text.lower() for c in result.content)
        assert "blocked" in text or "forbidden" in text


@pytest.mark.asyncio
async def test_mcp_invalid_ko_type_returns_error():
    async with _mcp_session() as session:
        result = await session.call_tool(
            "splunk_get_knowledge_objects", {"type": "nonexistent_type"}
        )
        assert result.isError is True


@pytest.mark.asyncio
async def test_mcp_run_query_row_limit():
    async with _mcp_session() as session:
        result = await session.call_tool(
            "splunk_run_query",
            {"query": "| makeresults count=10", "row_limit": 3},
        )
        assert result.isError is False
        data = json.loads(result.content[0].text)
        assert len(data["results"]) == 3
        assert data["truncated"] is True


@pytest.mark.asyncio
async def test_mcp_run_saved_search_nonexistent():
    async with _mcp_session() as session:
        result = await session.call_tool(
            "splunk_run_saved_search",
            {"saved_search_name": "nonexistent_abc_xyz_99999"},
        )
        assert result.isError is True
        text = " ".join(c.text.lower() for c in result.content)
        assert "unable to find" in text or "not found" in text
