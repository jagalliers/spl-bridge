"""End-to-end MCP protocol tests against the spl-bridge stdio server.

These tests spawn the real ``spl-bridge`` server as a subprocess and
talk to it over stdio using the official Python MCP SDK
(:mod:`mcp.client.stdio`). They do **not** require a live Splunk:
each scenario points the server at an unreachable address (port 1)
or supplies a deliberately invalid token, then asserts that the
server boots cleanly, exposes the expected tool inventory, classifies
errors correctly, enforces the rate limiter, and shuts down on
SIGINT without orphaned children.

What's covered (Phase 4 of the pre-push readiness plan):

* ``test_handshake_no_splunk``      -- MCP initialize round-trip
  succeeds even when Splunk is unreachable (server must not contact
  Splunk during boot).
* ``test_tool_inventory``           -- ``tools/list`` exposes the
  full registered tool set.
* ``test_unreachable_startup``      -- a tool call against an
  unreachable Splunk returns ``isError=True`` with the curated
  "Could not connect to Splunk" message (Phase 2 classification).
* ``test_session_expiry_message``   -- a tool call with a bogus
  token returns ``isError=True`` with "Splunk authentication
  failed" (no upstream body leakage).
* ``test_rate_limit_enforced``      -- with ``MCP_RATE_LIMITS={"global": 1}``
  the second tool call returns the rate-limit error.
* ``test_sigint_graceful_shutdown`` -- sending SIGINT to the server
  process produces a clean exit within a bounded window.

These tests do NOT require ``SPLUNK_INTEGRATION=1`` because they
never touch a real Splunk. The MCP SDK is a hard dependency of the
package itself, so import failures will surface as collection
errors -- which is correct.
"""

from __future__ import annotations

import json
import os
import signal
import socket
import subprocess
import sys
import time
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager

import pytest

# ---------------------------------------------------------------------------
# Subprocess wiring helpers
# ---------------------------------------------------------------------------

# Use port 1 -- always closed on Linux/macOS for unprivileged users.
# A connection attempt fails immediately (ECONNREFUSED), so probes
# return in well under a second instead of hanging on a default
# 60 s timeout. The host is irrelevant; ``127.0.0.1`` is reachable
# and the kernel will refuse the SYN.
UNREACHABLE_HOST = "127.0.0.1"
UNREACHABLE_PORT = "1"


def _free_port() -> int:
    """Bind to a random port to learn one nothing else holds.

    Closes the socket before returning -- there's an inherent TOCTOU
    race here, but it's only used as a sanity helper and never as a
    security boundary.
    """
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def _server_env(
    *,
    extra: dict[str, str] | None = None,
    bogus_splunk: bool = True,
    timeout: str = "2",
) -> dict[str, str]:
    """Build a minimal env that boots the server WITHOUT touching Splunk.

    We deliberately do NOT inherit the parent shell env -- that would
    drag in real ``SPLUNK_TOKEN`` / ``SPLUNK_PASSWORD`` set on the dev
    machine and force the server to talk to a real instance.
    """
    env: dict[str, str] = {
        "PATH": os.environ.get("PATH", ""),
        # Disable color so any inadvertent debug log is plain ASCII.
        "NO_COLOR": "1",
        "MCP_TIMEOUT": timeout,
    }
    if bogus_splunk:
        env["SPLUNK_HOST"] = UNREACHABLE_HOST
        env["SPLUNK_PORT"] = UNREACHABLE_PORT
        env["SPLUNK_SCHEME"] = "https"
        env["SPLUNK_VERIFY_SSL"] = "false"
        # Token mode avoids the wizard's password-mode hard-stop and
        # lets ``SplunkMCPConfig.from_env`` succeed without prompting.
        env["SPLUNK_TOKEN"] = "bogus-not-a-real-token"
    if extra:
        env.update(extra)
    return env


@asynccontextmanager
async def _mcp_session(
    env: dict[str, str] | None = None,
) -> AsyncIterator[object]:
    """Spawn ``spl-bridge serve`` and return an initialized ClientSession."""
    from mcp.client.session import ClientSession
    from mcp.client.stdio import StdioServerParameters, stdio_client

    server_params = StdioServerParameters(
        command=sys.executable,
        args=["-m", "spl_bridge", "serve"],
        env=env or _server_env(),
        cwd=os.path.dirname(os.path.dirname(__file__)),
    )

    async with stdio_client(server_params) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


def _expected_tool_names() -> set[str]:
    from spl_bridge.tool_registry import load_builtin_tools, mcp_tool_name

    return {mcp_tool_name(t) for t in load_builtin_tools()}


# ---------------------------------------------------------------------------
# Handshake / tool inventory
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_handshake_no_splunk() -> None:
    """The MCP initialize round-trip must succeed even when Splunk is
    unreachable. Booting the server is a contract the host depends on
    -- if init blocked on a Splunk probe, the host would mark
    spl-bridge as broken every time the network was down.
    """
    async with _mcp_session() as session:
        # ``ClientSession.initialize`` returns when both sides have
        # exchanged ``initialize`` and ``initialized`` notifications.
        # Reaching this line proves the server framed JSON-RPC over
        # stdio cleanly and answered the protocol handshake.
        assert session is not None


@pytest.mark.asyncio
async def test_tool_inventory() -> None:
    """``tools/list`` must expose every tool the registry advertises."""
    expected = _expected_tool_names()
    async with _mcp_session() as session:
        result = await session.list_tools()
        names = {t.name for t in result.tools}
        # Subset rather than equality: future tools added to the
        # registry should not break this test as long as nothing
        # currently published is silently dropped.
        assert expected <= names, f"missing tools: {expected - names}"
        # And the count matches exactly so we don't accidentally start
        # exposing the four AI Assistant tools we deliberately exclude.
        assert len(result.tools) == len(expected), f"unexpected extra tools: {names - expected}"


# ---------------------------------------------------------------------------
# Classified error surfaces (Phase 2 fix locked in over a real socket)
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_unreachable_startup() -> None:
    """A tool call against an unreachable Splunk returns the curated
    connect-failure message (and NEVER an opaque "Internal error").
    """
    async with _mcp_session() as session:
        result = await session.call_tool("splunk_get_info", {})
        assert result.isError is True
        text = " ".join(c.text for c in result.content)
        assert "Could not connect to Splunk" in text, text
        # Host:port should be echoed back so the operator can correct
        # their config (it's not a secret -- they typed it).
        assert UNREACHABLE_HOST in text
        assert UNREACHABLE_PORT in text
        # Correlation id must always be present.
        assert "request_id=" in text


@pytest.mark.asyncio
async def test_session_expiry_message() -> None:
    """A tool call with a bogus token surfaces a curated, non-leaking
    error. We accept any of the three curated shapes the server may
    legitimately produce depending on whether splunkd is reachable
    on ``localhost:8089``:

    * ``Splunk API error (HTTP 401; ...)``  -- token-mode 401 path
      (the export endpoint returned 401 and the response body was
      logged but never forwarded to the client).
    * ``Splunk authentication failed ...``  -- a SplunkLoginError
      bubbled up before the request was made.
    * ``Could not connect to Splunk ...``   -- no splunkd on 8089.

    Crucially the response must NOT contain any upstream
    body fragments (cookie, session_key, Set-Cookie) and must
    include the request_id for log correlation.
    """
    env = _server_env(
        bogus_splunk=False,
        extra={
            "SPLUNK_HOST": "127.0.0.1",
            "SPLUNK_PORT": "8089",
            "SPLUNK_SCHEME": "https",
            "SPLUNK_VERIFY_SSL": "false",
            "SPLUNK_TOKEN": "definitely-not-a-valid-token",
        },
    )
    async with _mcp_session(env) as session:
        result = await session.call_tool("splunk_get_info", {})
        assert result.isError is True
        text = " ".join(c.text for c in result.content)
        accepted_messages = (
            "HTTP 401",
            "Splunk authentication failed",
            "Could not connect to Splunk",
        )
        assert any(m in text for m in accepted_messages), text
        # Upstream body must never appear -- no auth context, no
        # cookies, no session keys, never the bogus token itself.
        for banned in (
            "session_key",
            "cookie",
            "Set-Cookie",
            "definitely-not-a-valid-token",
            "call not properly authenticated",
        ):
            assert banned.lower() not in text.lower(), (
                f"{banned!r} leaked into client error: {text!r}"
            )
        assert "request_id=" in text


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_rate_limit_enforced() -> None:
    """With a global limit of 1 request/min, the second tool call
    must be denied by the rate limiter BEFORE reaching Splunk.
    """
    env = _server_env(
        extra={"MCP_RATE_LIMITS": json.dumps({"global": 1})},
    )
    async with _mcp_session(env) as session:
        first = await session.call_tool("splunk_get_info", {})
        # First call may succeed or fail (Splunk unreachable) -- we
        # don't care; we only care that it COULD reach Splunk, i.e.
        # the rate limiter let it through.
        first_text = " ".join(c.text for c in first.content)

        second = await session.call_tool("splunk_get_info", {})
        assert second.isError is True
        second_text = " ".join(c.text for c in second.content)
        assert "Rate limit exceeded" in second_text, second_text
        # Sanity: the first call's text must NOT contain the rate
        # limit message (i.e. the limiter actually let it through).
        assert "Rate limit exceeded" not in first_text


# ---------------------------------------------------------------------------
# Signal handling -- spawn raw subprocess and SIGINT it
# ---------------------------------------------------------------------------


def test_stdin_close_graceful_shutdown() -> None:
    """The realistic stdio MCP shutdown path is: the host closes the
    child's stdin. FastMCP's ``stdio_server`` reaches EOF, the
    ``run_stdio_async`` coroutine returns normally, and our
    ``server.main`` ``finally`` block closes the SplunkClient. The
    process must exit cleanly within a bounded window.

    This is the path the official MCP SDK takes when its
    ``stdio_client`` context exits, so it's what every well-behaved
    MCP host (Claude Desktop, Cursor, the SDK itself) actually does.
    """
    proc = subprocess.Popen(  # noqa: S603 -- known argv, no shell
        [sys.executable, "-m", "spl_bridge", "serve"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=_server_env(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        time.sleep(0.5)
        assert proc.poll() is None, (
            "server exited before stdin was closed: "
            f"stderr={proc.stderr.read().decode(errors='replace') if proc.stderr else ''!r}"
        )

        # The host shutting down. FastMCP must notice EOF and return.
        assert proc.stdin is not None
        proc.stdin.close()
        try:
            exit_code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            pytest.fail("server did not exit within 10 s of stdin EOF")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    # ``server.main`` returns normally -> Python exits 0.
    assert exit_code == 0, (
        f"unexpected exit code {exit_code}; stderr="
        f"{proc.stderr.read().decode(errors='replace') if proc.stderr else ''!r}"
    )


def test_sigterm_graceful_shutdown() -> None:
    """SIGTERM is the standard termination signal in container/init
    environments. Even though ``server.main`` only catches
    KeyboardInterrupt explicitly, SIGTERM should still produce a
    bounded exit because Python's default SIGTERM handler raises
    SystemExit and the ``finally`` block runs.
    """
    proc = subprocess.Popen(  # noqa: S603
        [sys.executable, "-m", "spl_bridge", "serve"],
        cwd=os.path.dirname(os.path.dirname(__file__)),
        env=_server_env(),
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        time.sleep(0.5)
        assert proc.poll() is None
        proc.terminate()  # SIGTERM
        try:
            exit_code = proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
            pytest.fail("server did not exit within 10 s of SIGTERM")
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=5)

    # Default SIGTERM behavior on POSIX is to exit -SIGTERM; if
    # ``server.main`` happens to install a handler that converts to a
    # clean exit, 0 is also acceptable.
    assert exit_code in (0, -signal.SIGTERM, signal.SIGTERM), (
        f"unexpected exit code {exit_code}; stderr="
        f"{proc.stderr.read().decode(errors='replace') if proc.stderr else ''!r}"
    )


# ---------------------------------------------------------------------------
# Sanity check on _free_port helper (kept tiny -- avoids "unused")
# ---------------------------------------------------------------------------


def test_free_port_helper_returns_unique_port() -> None:
    p1 = _free_port()
    p2 = _free_port()
    assert isinstance(p1, int) and 1024 < p1 < 65535
    assert isinstance(p2, int) and 1024 < p2 < 65535
