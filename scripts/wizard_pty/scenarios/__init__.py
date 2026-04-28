"""Wizard PTY scenarios.

Each scenario module exports a single :class:`Scenario` instance via a
top-level ``SCENARIO`` attribute. The runner imports each module on
demand and dispatches based on the name passed on the command line.

To add a new scenario:

1. Drop a new ``my_scenario.py`` next to the existing ones.
2. Define ``SCENARIO = Scenario(name="my_scenario", run=...)``.
3. Add ``"my_scenario"`` to :data:`SCENARIO_NAMES` below.
"""

from __future__ import annotations

# Order matters only for the default "run all" path -- we run cheap
# scenarios first so a failure surfaces early.
SCENARIO_NAMES: list[str] = [
    "snippet_only",
    "password_cursor",
    "token_cursor",
    "password_ca_bundle",
    "bad_password_recovery",
    "idempotent_rerun",
    "claude_desktop",
    "claude_cli",
    "dotfile_fallback",
]
