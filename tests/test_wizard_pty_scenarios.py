"""Pytest collector for the PTY wizard scenarios.

These tests are opt-in because they:
* spawn a real ``spl-bridge setup`` process on a pseudo-terminal,
* exercise the OS keychain (writes + deletes a sentinel row),
* require a live lab Splunk reachable on ``SPLUNK_SMOKETEST_HOST``,
* require the lab password in ``SPLUNK_SMOKETEST_PASSWORD``.

To opt in, set ``WIZARD_PTY_TESTS=1`` and supply the Splunk env vars::

    WIZARD_PTY_TESTS=1 \\
    SPLUNK_SMOKETEST_PASSWORD='lab-pw' \\
        pytest -m pty -v

In normal CI (which does not have a Splunk available) the file is
collected but every test is skipped at collection time -- this keeps
the suite green without forcing every developer to maintain a lab
environment.
"""

from __future__ import annotations

import importlib
import os
import sys
from pathlib import Path

import pytest

_REPO_ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(_REPO_ROOT))

from scripts.wizard_pty.scenarios import SCENARIO_NAMES  # noqa: E402

PTY_OPT_IN = os.environ.get("WIZARD_PTY_TESTS") == "1"


pytestmark = [
    pytest.mark.pty,
    pytest.mark.skipif(
        not PTY_OPT_IN,
        reason=(
            "PTY wizard scenarios are opt-in. "
            "Set WIZARD_PTY_TESTS=1 plus SPLUNK_SMOKETEST_PASSWORD."
        ),
    ),
]


@pytest.mark.parametrize("scenario_name", SCENARIO_NAMES)
def test_wizard_scenario(scenario_name: str) -> None:
    mod = importlib.import_module(f"scripts.wizard_pty.scenarios.{scenario_name}")
    sc = mod.SCENARIO
    report = sc.run()
    if not report.ok:
        # Surface artefact problems + transcript tail in the failure
        # message for fast triage; pytest -v will show the full thing.
        from scripts.wizard_pty.scenarios._base import strip_ansi

        tail = "\n".join(strip_ansi(report.pty.transcript).splitlines()[-40:])
        problems = "\n  - ".join(report.artefact_problems) or "(none)"
        notes = "\n  - ".join(report.notes) or "(none)"
        pytest.fail(
            "\n".join(
                [
                    f"Scenario {scenario_name!r} FAILED",
                    f"  exit_status: {report.pty.exit_status}",
                    f"  timed_out_on: {report.pty.timed_out_on!r}",
                    "  problems:",
                    f"  - {problems}",
                    "  notes:",
                    f"  - {notes}",
                    "  --- last 40 lines of transcript ---",
                    tail,
                ]
            )
        )
