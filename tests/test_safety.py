"""Safety and security tests for spl-bridge.

Unit tests (no Splunk required) exercise the defensive code paths added in
the security gap fixes.  Integration tests at the bottom are gated behind
SPLUNK_INTEGRATION=1 and run adversarial queries through the full MCP
round-trip against a live Splunk instance.
"""

from __future__ import annotations

import json
import os
import sys
from contextlib import asynccontextmanager
from typing import Any
from unittest.mock import MagicMock

import pytest

from spl_bridge.rate_limit import RateLimitManager
from spl_bridge.server import (
    MAX_JSON_DEPTH,
    MAX_PAYLOAD_BYTES,
    ToolExecutionError,
    _check_json_depth,
    _validate_args,
)
from spl_bridge.tool_registry import load_safe_spl

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_tool_schema(
    properties: dict[str, Any],
    required: list[str] | None = None,
) -> dict[str, Any]:
    schema: dict[str, Any] = {"type": "object", "properties": properties}
    if required:
        schema["required"] = required
    return {"inputSchema": schema}


# ---------------------------------------------------------------------------
# 1. Pattern validation (Gap 3 -- re.fullmatch)
# ---------------------------------------------------------------------------


class TestPatternValidation:
    """re.fullmatch must reject values that only partially match."""

    def test_partial_match_rejected(self) -> None:
        tool = _make_tool_schema(
            {
                "name": {
                    "type": "string",
                    "pattern": "[a-z]+",
                },
            }
        )
        err = _validate_args(tool, {"name": "abc; | delete"})
        assert err is not None

    def test_full_match_accepted(self) -> None:
        tool = _make_tool_schema(
            {
                "name": {
                    "type": "string",
                    "pattern": "[a-z]+",
                },
            }
        )
        err = _validate_args(tool, {"name": "abc"})
        assert err is None

    def test_anchored_pattern_still_works(self) -> None:
        tool = _make_tool_schema(
            {
                "idx": {
                    "type": "string",
                    "pattern": "^[a-zA-Z0-9_-]+$",
                },
            }
        )
        assert _validate_args(tool, {"idx": "main"}) is None
        assert _validate_args(tool, {"idx": "bad; stuff"}) is not None

    def test_custom_validation_message(self) -> None:
        tool = _make_tool_schema(
            {
                "idx": {
                    "type": "string",
                    "pattern": "^[a-z]+$",
                    "validation_message": "Only lowercase letters",
                },
            }
        )
        err = _validate_args(tool, {"idx": "ABC"})
        assert err == "Only lowercase letters"


# ---------------------------------------------------------------------------
# 2. JSON depth check (Gap 4 -- iterative stack)
# ---------------------------------------------------------------------------


class TestJsonDepthCheck:
    @staticmethod
    def _nested(depth: int) -> dict:
        obj: dict = {"leaf": True}
        for _ in range(depth - 1):
            obj = {"child": obj}
        return obj

    def test_at_max_depth_passes(self) -> None:
        assert _check_json_depth(self._nested(MAX_JSON_DEPTH)) is True

    def test_one_over_max_depth_fails(self) -> None:
        assert _check_json_depth(self._nested(MAX_JSON_DEPTH + 1)) is False

    def test_extreme_depth_no_stack_overflow(self) -> None:
        deep = self._nested(2000)
        assert _check_json_depth(deep) is False

    def test_flat_dict_passes(self) -> None:
        assert _check_json_depth({"a": 1, "b": 2}) is True

    def test_flat_list_passes(self) -> None:
        assert _check_json_depth([1, 2, 3]) is True

    def test_scalar_passes(self) -> None:
        assert _check_json_depth("hello") is True


# ---------------------------------------------------------------------------
# 3. Payload size limit
# ---------------------------------------------------------------------------


class TestPayloadSizeLimit:
    def test_oversized_payload_rejected(self) -> None:
        from spl_bridge.config import SplunkMCPConfig

        config = SplunkMCPConfig(host="mock", splunk_token="tok")
        client = MagicMock()

        big_value = "x" * (MAX_PAYLOAD_BYTES + 1)
        with pytest.raises(ToolExecutionError, match="maximum size"):
            _invoke_execute_tool(config, client, "splunk_run_query", {"query": big_value})


# ---------------------------------------------------------------------------
# 4. Rate limiting enforcement
# ---------------------------------------------------------------------------


class TestRateLimitEnforcement:
    def test_global_limit_blocks_after_max(self) -> None:
        mgr = RateLimitManager(global_max=3, window_seconds=60.0)
        assert mgr.check("tool_a") is True
        assert mgr.check("tool_a") is True
        assert mgr.check("tool_a") is True
        assert mgr.check("tool_a") is False

    def test_per_tool_limit_independent(self) -> None:
        mgr = RateLimitManager(global_max=100, window_seconds=60.0)
        mgr.set_tool_limit("expensive", 2)
        assert mgr.check("expensive") is True
        assert mgr.check("expensive") is True
        assert mgr.check("expensive") is False
        assert mgr.check("other_tool") is True


# ---------------------------------------------------------------------------
# 5. Saved search not-found blocking (Gap 2)
# ---------------------------------------------------------------------------


class TestSavedSearchBlocking:
    def test_not_found_raises_error(self) -> None:
        from spl_bridge.config import SplunkMCPConfig

        config = SplunkMCPConfig(host="mock", splunk_token="tok")
        client = MagicMock()
        client.is_saved_search_disabled.return_value = (
            False,
            "Saved search 'bogus' not found.",
            None,
        )

        with pytest.raises(ToolExecutionError, match="not found"):
            _invoke_execute_tool(
                config,
                client,
                "splunk_run_saved_search",
                {
                    "saved_search_name": "bogus",
                },
            )

    def test_app_mismatch_raises_error(self) -> None:
        from spl_bridge.config import SplunkMCPConfig

        config = SplunkMCPConfig(host="mock", splunk_token="tok")
        client = MagicMock()
        client.is_saved_search_disabled.return_value = (
            False,
            "Saved search is enabled.",
            "search",
        )

        with pytest.raises(ToolExecutionError, match="belongs to app"):
            _invoke_execute_tool(
                config,
                client,
                "splunk_run_saved_search",
                {
                    "saved_search_name": "my_search",
                    "app": "wrong_app",
                },
            )


def _invoke_execute_tool(
    config: Any,
    client: Any,
    tool_name: str,
    arguments: dict[str, Any],
) -> dict[str, Any]:
    """Build the MCP app and invoke _execute_tool for the given tool name."""
    from spl_bridge.server import _build_mcp_app

    _build_mcp_app(config, client)

    from spl_bridge.rate_limit import RateLimitManager as RL
    from spl_bridge.server import (
        MAX_PAYLOAD_BYTES,
        ToolExecutionError,
        _check_json_depth,
        _validate_args,
    )
    from spl_bridge.splunk_client import normalize_search_command
    from spl_bridge.tool_registry import (
        _SAVEDSEARCH_RE,
        build_spl,
        load_builtin_tools,
        load_generating_commands,
        load_safe_spl,
        mcp_tool_name,
    )

    tools = load_builtin_tools()
    safety = load_safe_spl()
    generating = load_generating_commands()
    safe_commands = set(safety.get("safe_spl_commands", []))
    exclude_tools = set(safety.get("exclude_tools", []))
    sub_search_arg_cmd = safety.get("sub_search_arg_cmd", {})

    tool_by_name = {}
    for t in tools:
        name = mcp_tool_name(t)
        tool_by_name[name] = t

    rate_limiter = RL(global_max=600, window_seconds=60.0)

    args_json = json.dumps(arguments, default=str)
    if len(args_json.encode()) > MAX_PAYLOAD_BYTES:
        raise ToolExecutionError("Argument payload exceeds maximum size")
    if not _check_json_depth(arguments):
        raise ToolExecutionError("Argument nesting exceeds maximum depth")

    if not rate_limiter.check(tool_name):
        raise ToolExecutionError("Rate limit exceeded. Try again shortly.")

    tool_def = tool_by_name.get(tool_name)
    if tool_def is None:
        raise ToolExecutionError(f"Unknown tool: {tool_name}")

    validation_err = _validate_args(tool_def, arguments)
    if validation_err:
        raise ToolExecutionError(validation_err)

    template = tool_def.get("_meta", {}).get("execution", {}).get("template", "")
    match = _SAVEDSEARCH_RE.match(template)
    if match:
        ss_name_field = match.group(1)
        ss_name = arguments.get(ss_name_field, "")
        if ss_name:
            ss_app = arguments.get("app")
            disabled, msg, resolved_app = client.is_saved_search_disabled(ss_name, app=ss_app)
            if disabled:
                raise ToolExecutionError(msg)
            if resolved_app is None:
                raise ToolExecutionError(msg)
            if ss_app and ss_app != resolved_app:
                raise ToolExecutionError(
                    f"Saved search '{ss_name}' belongs to app "
                    f"'{resolved_app}', not '{ss_app}'. "
                    f"Use app='{resolved_app}' or omit the app "
                    f"parameter to auto-resolve."
                )
            if not ss_app:
                arguments["app"] = resolved_app

    try:
        spl, row_limit, earliest, latest = build_spl(
            tool_def,
            arguments,
            default_row_limit=config.default_row_limit,
            max_row_limit=config.max_row_limit,
        )
    except ValueError as exc:
        raise ToolExecutionError(str(exc)) from exc

    if not spl.strip():
        raise ToolExecutionError("Generated SPL query is empty")

    effective_limit = row_limit if row_limit else config.default_row_limit

    normalized = normalize_search_command(spl, config.max_row_limit, generating)

    skip_safety = tool_name in exclude_tools
    if not skip_safety:
        is_safe, reason = client.check_spl_safe(normalized, safe_commands, sub_search_arg_cmd)
        if not is_safe:
            raise ToolExecutionError(f"Query blocked by safety check: {reason}")

    result = client.export_search(
        query=normalized,
        earliest_time=earliest,
        latest_time=latest,
        row_limit=effective_limit,
        app=arguments.get("app"),
    )

    if "error" in result:
        raise ToolExecutionError(result["error"])

    return result


# ---------------------------------------------------------------------------
# 6. Exclude-tools bypass verification
# ---------------------------------------------------------------------------


class TestExcludeToolsBypass:
    def test_exclude_tools_contents(self) -> None:
        safety = load_safe_spl()
        exclude = set(safety.get("exclude_tools", []))
        assert "splunk_get_info" in exclude
        assert "splunk_get_indexes" in exclude
        assert "splunk_run_query" not in exclude

    def test_rest_not_in_safe_commands(self) -> None:
        safety = load_safe_spl()
        safe = set(safety.get("safe_spl_commands", []))
        assert "rest" not in safe


# ---------------------------------------------------------------------------
# Integration tests -- adversarial SPL via live MCP round-trip
# ---------------------------------------------------------------------------

integration = pytest.mark.skipif(
    os.environ.get("SPLUNK_INTEGRATION") != "1",
    reason="Set SPLUNK_INTEGRATION=1 to run live Splunk tests",
)


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
    """Build a minimal subprocess env that does NOT leak unrelated secrets."""
    env: dict[str, str] = {"PATH": os.environ.get("PATH", "")}
    for var in _FORWARDED_VARS:
        if var in os.environ:
            env[var] = os.environ[var]
    env.setdefault("SPLUNK_HOST", "localhost")
    env.setdefault("SPLUNK_PORT", "8089")
    env.setdefault("SPLUNK_VERIFY_SSL", "false")
    return env


@asynccontextmanager
async def _mcp_session():
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


@integration
@pytest.mark.asyncio
async def test_rest_command_blocked_via_mcp():
    async with _mcp_session() as session:
        result = await session.call_tool(
            "splunk_run_query", {"query": "| rest /services/server/info"}
        )
        assert result.isError is True
        text = " ".join(c.text.lower() for c in result.content)
        assert "blocked" in text or "forbidden" in text


@integration
@pytest.mark.asyncio
async def test_delete_command_blocked_via_mcp():
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_run_query", {"query": "| delete index=main"})
        assert result.isError is True
        text = " ".join(c.text.lower() for c in result.content)
        assert "blocked" in text or "forbidden" in text


@integration
@pytest.mark.asyncio
async def test_script_command_blocked_via_mcp():
    async with _mcp_session() as session:
        result = await session.call_tool(
            "splunk_run_query", {"query": "| script python malicious.py"}
        )
        assert result.isError is True
        text = " ".join(c.text.lower() for c in result.content)
        assert "blocked" in text or "forbidden" in text


@integration
@pytest.mark.asyncio
async def test_unsafe_subsearch_blocked_via_mcp():
    async with _mcp_session() as session:
        result = await session.call_tool(
            "splunk_run_query",
            {"query": "search index=main [| rest /services/server/info]"},
        )
        assert result.isError is True
        text = " ".join(c.text.lower() for c in result.content)
        assert "blocked" in text or "forbidden" in text or "rest" in text


@integration
@pytest.mark.asyncio
async def test_invalid_ko_type_rejected_via_mcp():
    async with _mcp_session() as session:
        result = await session.call_tool(
            "splunk_get_knowledge_objects",
            {"type": "| rest /etc/passwd"},
        )
        assert result.isError is True


@integration
@pytest.mark.asyncio
async def test_saved_search_not_found_blocked_via_mcp():
    async with _mcp_session() as session:
        result = await session.call_tool(
            "splunk_run_saved_search",
            {"saved_search_name": "definitely_nonexistent_12345"},
        )
        assert result.isError is True
        text = " ".join(c.text.lower() for c in result.content)
        assert "not found" in text
