#!/usr/bin/env python3
"""CLI runner for the spl-bridge setup-wizard PTY scenarios.

Usage::

    # Run a single scenario
    SPLUNK_SMOKETEST_PASSWORD='lab-pw' \\
        python scripts/run_wizard_pty.py password_cursor

    # Run all scenarios in declared order
    SPLUNK_SMOKETEST_PASSWORD='lab-pw' \\
        python scripts/run_wizard_pty.py --all

    # List available scenarios
    python scripts/run_wizard_pty.py --list

Environment variables consumed by scenarios:

* ``SPLUNK_SMOKETEST_PASSWORD`` -- required for all
  username/password scenarios.
* ``SPLUNK_SMOKETEST_HOST`` -- defaults to ``localhost``.
* ``SPLUNK_SMOKETEST_PORT`` -- defaults to ``8089``.
* ``SPLUNK_SMOKETEST_USERNAME`` -- defaults to ``admin``.
* ``SPLUNK_SMOKETEST_TOKEN`` -- required only for ``token_cursor``.

Exits 0 if all selected scenarios pass, 1 if any fails, 2 on usage
error.
"""

from __future__ import annotations

import argparse
import importlib
import sys
from pathlib import Path

# Make ``scripts`` importable when run as a script (``__main__``).
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from scripts.wizard_pty.scenarios import SCENARIO_NAMES  # noqa: E402
from scripts.wizard_pty.scenarios._base import (  # noqa: E402
    Scenario,
    ScenarioReport,
    strip_ansi,
)


def _load(name: str) -> Scenario:
    if name not in SCENARIO_NAMES:
        raise SystemExit(f"error: unknown scenario {name!r}. Known: {', '.join(SCENARIO_NAMES)}")
    mod = importlib.import_module(f"scripts.wizard_pty.scenarios.{name}")
    sc = getattr(mod, "SCENARIO", None)
    if not isinstance(sc, Scenario):
        raise SystemExit(f"scenario module {name} missing SCENARIO export")
    return sc


def _print_report(report: ScenarioReport, *, verbose: bool) -> None:
    head = "PASS" if report.ok else "FAIL"
    sys.stdout.write(f"[{head}] {report.name}\n")
    for note in report.notes:
        sys.stdout.write(f"   note: {note}\n")
    for prob in report.artefact_problems:
        sys.stdout.write(f"   problem: {prob}\n")
    if not report.ok or verbose:
        sys.stdout.write(f"   exit: {report.pty.exit_status}\n")
        if report.pty.timed_out_on:
            sys.stdout.write(f"   timed_out_on: {report.pty.timed_out_on!r}\n")
        if verbose and report.pty.transcript:
            sys.stdout.write("   --- TRANSCRIPT (ANSI stripped) ---\n")
            for line in strip_ansi(report.pty.transcript).splitlines():
                sys.stdout.write(f"   | {line}\n")
            sys.stdout.write("   --- END TRANSCRIPT ---\n")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Run setup-wizard PTY scenarios",
    )
    parser.add_argument(
        "scenarios",
        nargs="*",
        help="One or more scenario names (see --list)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Run every scenario in declared order",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="Print known scenarios and exit",
    )
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="Print transcript even on PASS",
    )
    args = parser.parse_args(argv)

    if args.list:
        for n in SCENARIO_NAMES:
            print(n)
        return 0

    if args.all:
        names = list(SCENARIO_NAMES)
    elif args.scenarios:
        names = args.scenarios
    else:
        parser.print_help(sys.stderr)
        return 2

    overall_ok = True
    for name in names:
        sc = _load(name)
        report = sc.run()
        _print_report(report, verbose=args.verbose)
        if not report.ok:
            overall_ok = False

    return 0 if overall_ok else 1


if __name__ == "__main__":
    sys.exit(main())
