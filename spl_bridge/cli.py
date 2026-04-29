"""CLI entry points for spl-bridge."""

from __future__ import annotations

import argparse
import logging

logger = logging.getLogger(__name__)


_TOP_DESCRIPTION = (
    "Splunk MCP stdio server. Speaks Model Context Protocol over stdio "
    "to an MCP host (Cursor, Claude Desktop, Claude CLI) and the public "
    "Splunk REST API on the other side."
)

_TOP_EPILOG = (
    "First-time setup:   spl-bridge setup        (interactive wizard)\n"
    "Verify connection:  spl-bridge doctor       (one-shot REST probe)\n"
    "Run the server:     spl-bridge serve        (default; usually launched\n"
    "                                             by the MCP host, not by hand)\n"
    "\n"
    "See README.md -> 'Setup' and 'Where credentials live' for the full story."
)

_SETUP_EPILOG = (
    "Five steps, with nothing persisted until step 4:\n"
    "  1. Prereq checks (Python, mcp/requests/platformdirs, keychain backend)\n"
    "  2. Splunk connection + auth mode (refuses unsafe combinations)\n"
    "  3. Live probe of /services/server/info before anything is saved\n"
    "  4. Stores secrets to OS keychain (preferred) or 0600 dotfile (fallback)\n"
    "  5. Writes the launch entry into your MCP host's JSON config\n"
    "     (Cursor, Claude Desktop, Claude CLI, or print-only snippet),\n"
    "     with a timestamped backup of any prior config.\n"
    "\n"
    "Requires a TTY -- the wizard refuses to run from a pipe so secrets\n"
    "cannot be silently fed in via stdin redirection. Re-run anytime to\n"
    "rotate credentials or change connection metadata; behaviour is\n"
    "idempotent."
)

_DOCTOR_EPILOG = (
    "Default mode (no flags):\n"
    "  Reads the same four credential sources the server uses (env -> _FILE\n"
    "  -> OS keychain -> 0600 dotfile) and walks TLS, auth, the search\n"
    "  parser, and the search export endpoint. Exits 0 on success and\n"
    "  prints a one-line diagnostic on failure.\n"
    "\n"
    "With --hosts:\n"
    "  Inspects MCP host JSON configs (Cursor user-scope, Claude Desktop)\n"
    "  for `spl-bridge` entries whose `command` is a bare basename rather\n"
    "  than an absolute path. PATH-stripped GUI hosts (notably Claude\n"
    "  Desktop on macOS) cannot resolve a bare `spl-bridge` and fail to\n"
    "  spawn. Splunk REST is NOT touched in this mode, so it works even\n"
    "  when the endpoint is unreachable. Exits 1 if any warnings emit."
)

_SERVE_EPILOG = (
    "Spawns the MCP stdio server. Stdout is reserved for length-framed\n"
    "JSON-RPC messages; logs go to stderr. Normally launched by the MCP\n"
    "host (whose JSON config points at this command). For manual\n"
    "invocation, run with stdout connected to your MCP client."
)


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="spl-bridge",
        description=_TOP_DESCRIPTION,
        epilog=_TOP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    sub = parser.add_subparsers(dest="command", metavar="{setup,doctor,serve}")
    sub.add_parser(
        "setup",
        help="Interactive setup wizard (recommended for first-time install)",
        description="Interactive setup wizard for spl-bridge.",
        epilog=_SETUP_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    doctor_parser = sub.add_parser(
        "doctor",
        help="One-shot Splunk connectivity check (or --hosts MCP config audit)",
        description="Verify the configured Splunk endpoint is reachable.",
        epilog=_DOCTOR_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    doctor_parser.add_argument(
        "--hosts",
        action="store_true",
        help=(
            "Audit MCP host JSON configs (Cursor, Claude Desktop) for "
            "spl-bridge entries with bare command names that may fail "
            "to launch from PATH-stripped GUI hosts. Skips Splunk REST "
            "checks entirely."
        ),
    )
    sub.add_parser(
        "serve",
        help="Run the MCP stdio server (default)",
        description="Run the MCP stdio server.",
        epilog=_SERVE_EPILOG,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    args = parser.parse_args()
    # R14: invoking the CLI with no subcommand defaults to ``serve``.
    if args.command is None:
        args.command = "serve"

    if args.command == "doctor":
        if args.hosts:
            from spl_bridge.doctor import run_host_scan

            run_host_scan()
        else:
            from spl_bridge.doctor import run_doctor

            run_doctor()
    elif args.command == "setup":
        import sys as _sys

        from spl_bridge.setup_wizard import main as setup_main

        _sys.exit(setup_main())
    else:
        from spl_bridge.server import main as serve

        serve()
