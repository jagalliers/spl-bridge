"""FastMCP stdio server exposing Splunk REST tools.

All logging goes to stderr.  stdout is reserved for MCP JSON-RPC frames.
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time as _time
from typing import Any

import requests
from mcp.server.fastmcp import FastMCP
from mcp.types import CallToolResult, TextContent

from spl_bridge import __version__ as _SPL_BRIDGE_VERSION
from spl_bridge.auth import SplunkLoginError
from spl_bridge.config import SplunkMCPConfig
from spl_bridge.logging_config import (
    clear_log_context,
    configure_logging,
    current_request_id,
    set_request_id,
    update_log_context,
)
from spl_bridge.rate_limit import RateLimitManager
from spl_bridge.splunk_client import SplunkClient, normalize_search_command
from spl_bridge.tool_registry import (
    _SAVEDSEARCH_RE,
    build_spl,
    load_builtin_tools,
    load_generating_commands,
    load_safe_spl,
    mcp_tool_name,
)

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES = 131_072
MAX_JSON_DEPTH = 32

# M5: Saved-search ``args`` are appended verbatim to the
# ``/saved/searches/{name}/dispatch`` POST body. We allow the characters
# that legitimate Splunk dispatch overrides need (``key=value`` pairs,
# quoted strings, simple punctuation, plain space/tab) and block anything
# that could pivot the request -- pipes, brackets, semicolons, newlines,
# carriage returns, backticks, ampersands.
# Note: ``\s`` is intentionally NOT used here because it would admit
# ``\n``/``\r``, defeating the line-injection defence.
_SAVED_SEARCH_ARGS_RE = re.compile(r"^[A-Za-z0-9_\-=.\"',:/+ \t]*$")


class ToolExecutionError(Exception):
    """Raised when a tool fails; FastMCP catches this and sets isError=True."""


def _check_json_depth(obj: Any, max_depth: int = MAX_JSON_DEPTH) -> bool:
    """Return False if *obj* exceeds *max_depth* nesting (iterative, stack-safe)."""
    stack: list[tuple[Any, int]] = [(obj, 1)]
    while stack:
        current, depth = stack.pop()
        if depth > max_depth:
            return False
        if isinstance(current, dict):
            for v in current.values():
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
        elif isinstance(current, list):
            for v in current:
                if isinstance(v, (dict, list)):
                    stack.append((v, depth + 1))
    return True


def _validate_args(tool: dict[str, Any], arguments: dict[str, Any]) -> str | None:
    """Lightweight schema validation; returns error message or None."""
    schema = tool.get("inputSchema", {})
    required = schema.get("required", [])
    properties = schema.get("properties", {})

    for field in required:
        if field not in arguments or arguments[field] is None:
            return f"Missing required argument: {field}"

    for field, value in arguments.items():
        prop = properties.get(field)
        if prop is None:
            continue
        type_ = prop.get("type")
        if type_ == "string":
            if not isinstance(value, str):
                return f"Invalid value for {field}: must be string"
            pattern = prop.get("pattern")
            if pattern and not re.fullmatch(pattern, value):
                msg = prop.get("validation_message", f"Invalid value for {field}")
                return str(msg)
        elif type_ == "integer":
            # bool is a subclass of int in Python; reject explicitly
            if isinstance(value, bool) or not isinstance(value, int):
                return f"Invalid value for {field}: must be integer"
        elif type_ == "boolean":
            if not isinstance(value, bool):
                return f"Invalid value for {field}: must be boolean"
        elif type_ == "number":
            if isinstance(value, bool) or not isinstance(value, (int, float)):
                return f"Invalid value for {field}: must be number"
        elif type_ == "array":
            if not isinstance(value, list):
                return f"Invalid value for {field}: must be array"
        elif type_ == "object":
            if not isinstance(value, dict):
                return f"Invalid value for {field}: must be object"

        enum_vals = prop.get("enum")
        if isinstance(enum_vals, list) and value not in enum_vals:
            return f"Invalid value for {field}: must be one of {enum_vals}"
    return None


def _format_success(result: dict[str, Any]) -> CallToolResult:
    """Build a CallToolResult with both ``content`` and ``structuredContent``.

    Returning a ``CallToolResult`` directly ensures the SDK passes it through
    unchanged -- giving us explicit control of both fields regardless of SDK
    version internals.

    * ``content``: full JSON-serialized text (what LLMs and all clients see)
    * ``structuredContent``: raw dict (for programmatic MCP clients)
    """
    serialized = json.dumps(result, indent=2, sort_keys=True, default=str)
    structured = result if isinstance(result, dict) else {"value": result}
    return CallToolResult(
        content=[TextContent(type="text", text=serialized)],
        structuredContent=structured,
        isError=False,
    )


def _build_mcp_app(
    config: SplunkMCPConfig,
    client: SplunkClient,
) -> FastMCP:
    tools = load_builtin_tools()
    safety = load_safe_spl()
    generating = load_generating_commands()
    safe_commands: set[str] = set(safety.get("safe_spl_commands", []))
    exclude_tools: set[str] = set(safety.get("exclude_tools", []))
    sub_search_arg_cmd: dict[str, list[str]] = safety.get("sub_search_arg_cmd", {})

    tool_by_name: dict[str, dict[str, Any]] = {}
    for t in tools:
        name = mcp_tool_name(t)
        tool_by_name[name] = t

    global_max = 600
    if config.rate_limits and "global" in config.rate_limits:
        global_max = config.rate_limits["global"]
    rate_limiter = RateLimitManager(global_max=global_max, window_seconds=60.0)

    if config.rate_limits:
        for tool_key, limit_val in config.rate_limits.items():
            if tool_key != "global":
                rate_limiter.set_tool_limit(tool_key, limit_val)

    mcp = FastMCP("spl-bridge")
    # FastMCP does not expose ``version`` in its public constructor;
    # without this assignment the MCP ``serverInfo.version`` reported
    # in the ``initialize`` handshake falls back to the upstream
    # ``mcp`` package version (see ``Server.create_initialization_options``
    # in mcp.server.lowlevel.server). Pin it to our own package version
    # so MCP clients see the bridge's release, not the framework's.
    mcp._mcp_server.version = _SPL_BRIDGE_VERSION

    def _execute_tool(tool_mcp_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        """Core execution path shared by all registered tools.

        Raises ToolExecutionError on failures so FastMCP sets isError=True.
        """
        set_request_id()
        update_log_context(tool_name=tool_mcp_name)
        _t0 = _time.monotonic()
        logger.info("Tool call started: %s", tool_mcp_name)
        try:
            if config.require_capabilities:
                ok, msg = client.ensure_capabilities_verified()
                if not ok:
                    raise ToolExecutionError(msg)

            try:
                return _execute_tool_inner(tool_mcp_name, arguments)
            except ToolExecutionError:
                raise
            except SplunkLoginError:
                # Login failures already include only the HTTP status
                # code or a generic phrase; they never embed the
                # response body. Surface a curated, operationally
                # useful message with the request id for correlation.
                logger.exception("Splunk login failed during tool %s", tool_mcp_name)
                raise ToolExecutionError(
                    f"Splunk authentication failed (request_id={current_request_id()})"
                ) from None
            except requests.Timeout:
                logger.exception("Splunk request timed out during tool %s", tool_mcp_name)
                raise ToolExecutionError(
                    "Splunk request timed out after "
                    f"{config.timeout}s (request_id={current_request_id()})"
                ) from None
            except requests.ConnectionError:
                # Includes DNS failures, refused TCP, TLS handshake
                # errors. The host:port is operator-known config (it's
                # what they typed into the wizard or env), so naming
                # it back to them is helpful, not a leak.
                logger.exception("Could not connect to Splunk during tool %s", tool_mcp_name)
                raise ToolExecutionError(
                    f"Could not connect to Splunk at {config.host}:{config.port}"
                    f" (request_id={current_request_id()})"
                ) from None
            except requests.RequestException:
                # Catch-all for other requests-level transport faults
                # (chunked encoding, content decoding, SSL verify
                # failures that aren't ConnectionError, etc.).
                logger.exception("Splunk transport error during tool %s", tool_mcp_name)
                raise ToolExecutionError(
                    "Splunk transport error talking to "
                    f"{config.host}:{config.port}"
                    f" (request_id={current_request_id()})"
                ) from None
            except Exception:
                logger.exception("Unhandled error in tool %s", tool_mcp_name)
                # ``from None`` deliberately drops the original
                # exception chain; the internal error message MUST
                # NOT leak provider details (host, stack, traceback)
                # to the MCP host. A correlated ``request_id`` lets
                # operators reconcile the sanitized client error
                # with the structured server log.
                raise ToolExecutionError(
                    f"Internal error processing tool (request_id={current_request_id()})"
                ) from None
        finally:
            elapsed = round(_time.monotonic() - _t0, 3)
            update_log_context(execution_time_seconds=elapsed)
            logger.info("Tool call finished: %s (%.3fs)", tool_mcp_name, elapsed)
            clear_log_context()

    def _execute_tool_inner(tool_mcp_name: str, arguments: dict[str, Any]) -> dict[str, Any]:
        args_json = json.dumps(arguments, default=str)
        if len(args_json.encode()) > MAX_PAYLOAD_BYTES:
            raise ToolExecutionError("Argument payload exceeds maximum size")
        if not _check_json_depth(arguments):
            raise ToolExecutionError("Argument nesting exceeds maximum depth")

        if not rate_limiter.check(tool_mcp_name):
            raise ToolExecutionError("Rate limit exceeded. Try again shortly.")

        tool_def = tool_by_name.get(tool_mcp_name)
        if tool_def is None:
            raise ToolExecutionError(f"Unknown tool: {tool_mcp_name}")

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

        skip_safety = tool_mcp_name in exclude_tools
        if not skip_safety:
            is_safe, reason = client.check_spl_safe(normalized, safe_commands, sub_search_arg_cmd)
            if not is_safe:
                logger.warning("SPL safety check failed for %s: %s", tool_mcp_name, reason)
                raise ToolExecutionError(f"Query blocked by safety check: {reason}")

        result = client.export_search(
            query=normalized,
            earliest_time=earliest,
            latest_time=latest,
            row_limit=effective_limit,
            app=arguments.get("app"),
            # Targeted error-ergonomics opt-in: only when the
            # originating tool is splunk_run_saved_search do we let
            # the client see a curated remediation hint for known
            # 400 patterns (e.g. missing token argument). Every
            # other tool keeps the always-redact wrapper.
            classify_400_as_savedsearch=(tool_def["name"] == "run_saved_search"),
        )

        if "error" in result:
            raise ToolExecutionError(result["error"])

        return result

    for tool_def in tools:
        name = mcp_tool_name(tool_def)
        description = tool_def.get("description", "")
        schema_props = tool_def.get("inputSchema", {}).get("properties", {})

        _register_tool(mcp, name, description, schema_props, _execute_tool)

    return mcp


def _register_tool(
    mcp: FastMCP,
    name: str,
    description: str,
    schema_props: dict[str, Any],
    execute_fn: Any,
) -> None:
    """Register a single tool on the FastMCP instance.

    We build a closure capturing ``name`` so each registered function
    calls ``execute_fn`` with the correct tool name.
    """
    param_names = list(schema_props.keys())

    if not param_names:

        @mcp.tool(name=name, description=description)
        def _no_args_tool() -> CallToolResult:
            return _format_success(execute_fn(name, {}))

        return

    has_query = "query" in param_names
    has_type = "type" in param_names and "query" not in param_names
    has_saved_search = "saved_search_name" in param_names
    has_index_name = "index_name" in param_names and not has_query

    if has_query:

        @mcp.tool(name=name, description=description)
        def _query_tool(
            query: str,
            earliest_time: str | None = None,
            latest_time: str | None = None,
            row_limit: int | None = None,
        ) -> CallToolResult:
            args: dict[str, Any] = {"query": query}
            if earliest_time is not None:
                args["earliest_time"] = earliest_time
            if latest_time is not None:
                args["latest_time"] = latest_time
            if row_limit is not None:
                args["row_limit"] = row_limit
            return _format_success(execute_fn(name, args))

        return

    if has_saved_search:

        @mcp.tool(name=name, description=description)
        def _saved_search_tool(
            saved_search_name: str,
            args: str = "",
            earliest_time: str | None = None,
            latest_time: str | None = None,
            app: str | None = None,
        ) -> CallToolResult:
            # M5: cap length first so a degenerate regex match never
            # walks a multi-MB string the user pasted by mistake.
            if len(args) > 4096:
                raise ToolExecutionError("saved-search args exceed 4096 characters")
            if args and not _SAVED_SEARCH_ARGS_RE.fullmatch(args):
                raise ToolExecutionError(
                    "Invalid characters in saved-search args. "
                    "Allowed: letters, digits, '_-=.,:/+', whitespace, "
                    "single/double quotes."
                )
            tool_args: dict[str, Any] = {"saved_search_name": saved_search_name}
            if args:
                tool_args["args"] = args
            if earliest_time is not None:
                tool_args["earliest_time"] = earliest_time
            if latest_time is not None:
                tool_args["latest_time"] = latest_time
            if app is not None:
                tool_args["app"] = app
            return _format_success(execute_fn(name, tool_args))

        return

    if has_type and "index" in param_names:

        @mcp.tool(name=name, description=description)
        def _type_index_tool(
            type: str,
            index: str = "*",
            earliest_time: str | None = None,
            latest_time: str | None = None,
            row_limit: int | None = None,
        ) -> CallToolResult:
            tool_args: dict[str, Any] = {"type": type, "index": index}
            if earliest_time is not None:
                tool_args["earliest_time"] = earliest_time
            if latest_time is not None:
                tool_args["latest_time"] = latest_time
            if row_limit is not None:
                tool_args["row_limit"] = row_limit
            return _format_success(execute_fn(name, tool_args))

        return

    if has_type:

        @mcp.tool(name=name, description=description)
        def _type_tool(type: str) -> CallToolResult:
            return _format_success(execute_fn(name, {"type": type}))

        return

    if has_index_name:

        @mcp.tool(name=name, description=description)
        def _index_name_tool(index_name: str) -> CallToolResult:
            return _format_success(execute_fn(name, {"index_name": index_name}))

        return

    # R10: a tool definition with declared parameters that does NOT match
    # any of the supported registration shapes is a programming error in
    # the bundled tool resources -- fail loudly at startup rather than
    # silently exposing a no-arg tool that ignores its parameters.
    raise RuntimeError(
        f"Tool {name!r} declares parameters {sorted(param_names)} but "
        "does not match any known registration shape. Update "
        "_register_tool to add a branch."
    )


def _assert_no_logging_to_stdout() -> None:
    """M7 (handler-level): assert no logging handler targets stdout.

    Under the MCP stdio transport, stdout carries length-framed
    JSON-RPC messages exclusively. A stray ``StreamHandler(sys.stdout)``
    -- e.g. installed by ``logging.basicConfig()`` somewhere up-stack --
    will inject log lines into that stream and cause the host client
    to fail to parse responses (typically as a hang).

    This walks every active logger and refuses to start the MCP server
    if any handler's stream is ``sys.stdout`` (or its underlying fd is
    file descriptor 1 distinct from stderr's fd). Set
    ``SPLUNK_MCP_ALLOW_STDOUT_LOGGING=1`` to opt out (only useful for
    tests with a non-stdio transport).
    """
    if os.environ.get("SPLUNK_MCP_ALLOW_STDOUT_LOGGING", "").strip() in {
        "1",
        "true",
        "yes",
        "on",
    }:
        return

    try:
        stdout_fd = sys.stdout.fileno()
    except (AttributeError, OSError, ValueError):
        stdout_fd = None

    seen: set[int] = set()
    loggers: list[logging.Logger] = [logging.getLogger()]
    loggers.extend(
        logging.getLogger(name)
        for name in list(logging.Logger.manager.loggerDict)
        if isinstance(logging.getLogger(name), logging.Logger)
    )
    for log in loggers:
        for handler in list(getattr(log, "handlers", []) or []):
            if id(handler) in seen:
                continue
            seen.add(id(handler))
            stream = getattr(handler, "stream", None)
            if stream is sys.stdout:
                raise RuntimeError(
                    "Refusing to start MCP stdio server: a logging "
                    f"handler ({type(handler).__name__} on logger "
                    f"{log.name!r}) is attached to sys.stdout. Move it "
                    "to sys.stderr or set "
                    "SPLUNK_MCP_ALLOW_STDOUT_LOGGING=1 (advanced)."
                )
            if stdout_fd is not None and stream is not None and hasattr(stream, "fileno"):
                try:
                    s_fd = stream.fileno()
                except (OSError, ValueError):
                    continue
                if s_fd == stdout_fd and stream is not sys.stderr:
                    raise RuntimeError(
                        "Refusing to start MCP stdio server: a logging "
                        f"handler ({type(handler).__name__}) targets "
                        "the same file descriptor as stdout. Move it to "
                        "stderr."
                    )


def main() -> None:
    """Run the MCP server over stdio."""
    configure_logging()

    config = SplunkMCPConfig.from_env()
    logger.info(
        "Starting spl-bridge (host=%s, port=%s, auth_mode=%s)",
        config.host,
        config.port,
        config.auth_mode,
    )

    client = SplunkClient(config)
    app = _build_mcp_app(config, client)
    _assert_no_logging_to_stdout()
    try:
        app.run(transport="stdio")
    except KeyboardInterrupt:
        logger.info("spl-bridge received KeyboardInterrupt; shutting down")
    finally:
        # M6: ensure the underlying requests.Session and any cached
        # password-mode session key are released before we exit, even
        # on SIGINT/SIGTERM. Any errors during shutdown are swallowed
        # so they cannot mask the original exception.
        try:
            client.close()
        except Exception:  # pragma: no cover - defensive
            logger.debug("Error while closing SplunkClient", exc_info=True)
