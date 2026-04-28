"""CLI entry points for spl-bridge."""

from __future__ import annotations

import argparse
import logging

logger = logging.getLogger(__name__)


def main() -> None:
    parser = argparse.ArgumentParser(prog="spl-bridge", description="Splunk MCP stdio server")
    sub = parser.add_subparsers(dest="command")
    sub.add_parser("serve", help="Run the MCP stdio server (default)")
    sub.add_parser("doctor", help="Test Splunk connectivity")
    sub.add_parser("setup", help="Interactive setup wizard")
    args = parser.parse_args()
    # R14: invoking the CLI with no subcommand defaults to ``serve``.
    if args.command is None:
        args.command = "serve"

    if args.command == "doctor":
        from spl_bridge.doctor import run_doctor

        run_doctor()
    elif args.command == "setup":
        import sys as _sys

        from spl_bridge.setup_wizard import main as setup_main

        _sys.exit(setup_main())
    else:
        from spl_bridge.server import main as serve

        serve()
